package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.util.Integers;

/**
 * RFC 9147 5.8.4 and 7. The owner of everything that happens on a DTLS 1.3 connection after the handshake has
 * completed: the post-handshake handshake messages, their reassembly, and the acknowledgements in both
 * directions.
 * <p>
 * The reliable handshake's own state - its flight tracker, its reassemblers, its ACK list - is scoped to a
 * flight and dies with {@link DTLSReliableHandshake#finish()}, which is why that method used to unregister the
 * record layer's ACK listener outright. This class is what it is handed to instead, and unlike the RFC 9147
 * 5.8.1 final-flight hook it is not bounded by the retransmit timeout: a KeyUpdate may arrive at any point in
 * a connection's life, so the owner lives as long as the connection does.
 * </p>
 * <p>
 * RFC 9147 5.8.4 describes the sending side as "independent state machines", one per message category, each
 * reducing to "waiting for an ACK and retransmitting the original message". The receiving side, implemented
 * here, is common to all of them: reassemble, dispatch by message type, acknowledge the record.
 * </p>
 */
class DTLS13PostHandshake
    implements DTLSAckListener
{
    /**
     * RFC 9147 6.1. Epoch 0 carries the initial plaintext messages and epoch 2 the rest of the handshake;
     * post-handshake messages arrive at epoch 3 and above. A handshake record below that epoch after the
     * handshake has completed is a retransmission of the peer's final flight, which belongs to the RFC 9147
     * 5.8.1 hook in {@link DTLSReliableHandshake#finish()} and not here.
     */
    static final int MIN_EPOCH = 3;

    /**
     * How far beyond the next expected message_seq a post-handshake message may be buffered. Post-handshake
     * messages are single-flight (RFC 9147 5.8.4), so reordering of more than a few is not a real case; the
     * bound is what stops a peer opening an unbounded number of reassembly buffers by sending an unbounded
     * number of message sequence numbers it never completes.
     */
    private static final int MAX_RECEIVE_AHEAD = 4;

    private final DTLSRecordLayer recordLayer;
    private final int maxHandshakeMessageSize;

    /**
     * RFC 9147 7.2. The record numbers of post-handshake messages we have sent and not yet seen acknowledged.
     * Nothing registers into it yet - the sending side arrives with key update - but the inbound ACK path it
     * exists for is wired up here, because that wiring is what was missing.
     */
    private final DTLS13FlightTracker flightTracker = new DTLS13FlightTracker();

    // message_seq -> DTLSReassembler, for messages not yet complete or not yet drained
    private final Hashtable currentInboundMessages = new Hashtable();

    /**
     * The handshake's message_seq space continues across the handshake boundary in both directions, so both
     * counters are carried over from the reliable handshake rather than restarted at zero. Two peers built
     * from this code would agree with each other either way; only one of the two is right on the wire.
     */
    private int next_send_seq;
    private int next_receive_seq;

    private int newSessionTicketCount = 0;
    private int keyUpdateCount = 0;

    /**
     * RFC 8446 4.6.3. Set when a received KeyUpdate asked for one in return, and cleared by the sending side
     * once it has sent one. The same latch TlsProtocol keeps ('keyUpdatePendingSend'), for the same reason:
     * the obligation is to send a KeyUpdate before the next Application Data record, not to send one from
     * inside the receive path.
     */
    private boolean keyUpdatePendingSend = false;

    DTLS13PostHandshake(DTLSRecordLayer recordLayer, int next_send_seq, int next_receive_seq,
        int maxHandshakeMessageSize)
    {
        this.recordLayer = recordLayer;
        this.next_send_seq = next_send_seq;
        this.next_receive_seq = next_receive_seq;
        this.maxHandshakeMessageSize = maxHandshakeMessageSize;
    }

    /**
     * RFC 9147 7.2. An ACK retires the fragments it names; a message all of whose fragments have been
     * acknowledged is no longer retransmitted.
     */
    public void receivedAck(Vector recordNumbers)
    {
        flightTracker.acknowledge(recordNumbers);
    }

    /**
     * Handle one deprotected handshake record received after the handshake completed.
     *
     * @param epoch the epoch the record was protected under, as resolved by the record layer.
     */
    void receivedHandshakeRecord(int epoch, byte[] buf, int off, int len)
        throws IOException
    {
        if (epoch < MIN_EPOCH)
        {
            return;
        }

        if (!processRecord(buf, off, len))
        {
            return;
        }

        /*
         * RFC 9147 7. "For post-handshake messages, ACKs SHOULD be sent once for each received and processed
         * handshake record ... This includes records containing messages which are discarded because a
         * previous copy has been received."
         *
         * That last sentence inverts the handshake-time rule, where a duplicate of an already complete message
         * draws no ACK (the flight's own timer batches it instead). After the handshake there is no flight and
         * no timer to batch against: the peer is retransmitting one message and waiting for one ACK, so an
         * unanswered duplicate means it retransmits for as long as its state machine runs.
         */
        DTLSRecordNumber recordNumber = recordLayer.getLastReceivedRecordNumber();
        if (null != recordNumber)
        {
            Vector recordNumbers = new Vector(1);
            recordNumbers.addElement(recordNumber);

            /*
             * RFC 9147 7. "After the handshake, implementations MUST use the highest available sending
             * epoch." sendAck writes at the current write epoch, which post-handshake is exactly that.
             */
            recordLayer.sendAck(recordNumbers);
        }
    }

    /**
     * @return true only if every message carried by the record was processed, buffered, or discarded as a
     *         duplicate, which is the RFC 9147 7 condition for acknowledging it. A record we dropped is not
     *         acknowledged: telling the peer not to retransmit something we discarded would lose it.
     */
    private boolean processRecord(byte[] buf, int off, int len)
        throws IOException
    {
        boolean accepted = false;

        while (len >= DTLSReliableHandshake.MESSAGE_HEADER_LENGTH)
        {
            int fragment_length = TlsUtils.readUint24(buf, off + 9);
            int message_length = fragment_length + DTLSReliableHandshake.MESSAGE_HEADER_LENGTH;
            if (len < message_length)
            {
                // NOTE: Truncated message - ignore it
                return false;
            }

            int length = TlsUtils.readUint24(buf, off + 1);
            int fragment_offset = TlsUtils.readUint24(buf, off + 6);
            if (fragment_offset + fragment_length > length)
            {
                // NOTE: Malformed fragment - ignore it and the rest of the record
                return false;
            }

            if (length > maxHandshakeMessageSize)
            {
                /*
                 * The reassembly buffer is sized from this peer-controlled length before anything in the
                 * message has been looked at, so an unbounded value is a memory exhaustion denial of service.
                 */
                return false;
            }

            short msg_type = TlsUtils.readUint8(buf, off + 0);

            checkPostHandshakeType(msg_type);

            int message_seq = TlsUtils.readUint16(buf, off + 4);

            if (message_seq < next_receive_seq)
            {
                /*
                 * RFC 9147 7. A message we have already processed. It is discarded, but the record carrying
                 * it is still acknowledged - see receivedHandshakeRecord.
                 */
                accepted = true;
            }
            else if (message_seq >= next_receive_seq + MAX_RECEIVE_AHEAD)
            {
                // NOTE: Too far ahead - ignore
                return false;
            }
            else
            {
                Integer key = Integers.valueOf(message_seq);

                DTLSReassembler reassembler = (DTLSReassembler)currentInboundMessages.get(key);
                if (null == reassembler)
                {
                    /*
                     * RFC 9147 5.8.3. A post-handshake message is fragmented exactly like a handshake one -
                     * a NewSessionTicket easily exceeds an MTU - so reassembly is not optional here, even
                     * though the other message we expect (KeyUpdate) has a one byte body.
                     */
                    reassembler = new DTLSReassembler(msg_type, length);
                    currentInboundMessages.put(key, reassembler);
                }

                if (reassembler.contributeFragment(msg_type, length, buf,
                        off + DTLSReliableHandshake.MESSAGE_HEADER_LENGTH, fragment_offset, fragment_length)
                    || reassembler.acceptsFragment(msg_type, length, fragment_offset, fragment_length))
                {
                    accepted = true;
                }
                else
                {
                    // NOTE: Inconsistent with a fragment already received - ignore it and the rest
                    return false;
                }
            }

            off += message_length;
            len -= message_length;
        }

        drainCompleteMessages();

        return accepted;
    }

    /**
     * RFC 8446 4.6 and RFC 9147 5.8.4. Only the post-handshake message types are legal here. Connection ID
     * messages are only legal once connection IDs have been negotiated and post-handshake client
     * authentication only once it has been offered; neither is supported, so both are as unexpected as any
     * other handshake message would be.
     */
    private void checkPostHandshakeType(short msg_type)
        throws IOException
    {
        switch (msg_type)
        {
        case HandshakeType.new_session_ticket:
        case HandshakeType.key_update:
            break;
        default:
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    private void drainCompleteMessages()
        throws IOException
    {
        for (;;)
        {
            Integer key = Integers.valueOf(next_receive_seq);

            DTLSReassembler reassembler = (DTLSReassembler)currentInboundMessages.get(key);
            if (null == reassembler)
            {
                return;
            }

            byte[] body = reassembler.getBodyIfComplete();
            if (null == body)
            {
                return;
            }

            currentInboundMessages.remove(key);
            next_receive_seq += 1;

            handleMessage(reassembler.getMsgType(), body);
        }
    }

    private void handleMessage(short msg_type, byte[] body)
        throws IOException
    {
        switch (msg_type)
        {
        case HandshakeType.new_session_ticket:
        {
            /*
             * The ticket is received and acknowledged, and then discarded: resumption and pre-shared keys are
             * not supported over DTLS 1.3, so there is nothing to offer it back on. Not acknowledging it
             * instead would leave the server retransmitting it for the life of its own state machine.
             */
            newSessionTicketCount += 1;
            break;
        }
        case HandshakeType.key_update:
        {
            /*
             * RFC 8446 4.6.3. The body is a single KeyUpdateRequest. It is validated before anything is acted
             * on, so that a malformed one is refused at the point it is parsed and never reaches the key
             * schedule - the update is irreversible, so it must not be started on a message that may still
             * turn out to be rejected.
             */
            if (1 != body.length)
            {
                throw new TlsFatalAlert(AlertDescription.decode_error);
            }

            short requestUpdate = TlsUtils.readUint8(body, 0);
            if (!KeyUpdateRequest.isValid(requestUpdate))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            /*
             * RFC 9147 8. The peer is updating its sending keys, so our read side moves with it: the peer's
             * next traffic secret is derived and the read epoch it keys is installed, while the epoch it
             * supersedes stays readable until a record decrypts under the new one.
             *
             * This happens before the ACK that receivedHandshakeRecord sends, which is only correct because
             * the two are independent: the ACK goes out at our own write epoch, which a peer's key update
             * does not move.
             */
            recordLayer.updatePeerReadEpoch();

            /*
             * RFC 8446 4.6.3. "If the request_update field is set to 'update_requested', then the receiver
             * MUST send a KeyUpdate of its own with request_update set to 'update_not_requested' prior to
             * sending its next Application Data record."
             *
             * Recorded as an obligation rather than sent from here, which is what TlsProtocol.receive13KeyUpdate
             * does too ('keyUpdatePendingSend |= updateRequested'); it does not send from the receive path
             * either. Over DTLS there is a second reason: sending a KeyUpdate is a state machine, not a write.
             * RFC 9147 5.8.4 makes it a single-flight message with its own retransmit timer, and section 8
             * forbids sending under the new epoch until it has been acknowledged, so the answer has to be
             * driven by the sending side, which owns those. Section 8 also overrides RFC 8446 here when the
             * epoch limit would be exceeded: the flag is then to be ignored rather than honoured, and that
             * judgement belongs with the sender too, which is the only side that knows its own epoch.
             */
            if (KeyUpdateRequest.update_requested == requestUpdate)
            {
                this.keyUpdatePendingSend = true;
            }

            keyUpdateCount += 1;
            break;
        }
        default:
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    /** RFC 9147 7.2. The outstanding post-handshake messages awaiting acknowledgement. */
    DTLS13FlightTracker getFlightTracker()
    {
        return flightTracker;
    }

    /** The message_seq the next post-handshake message we send will carry. */
    int getNextSendSeq()
    {
        return next_send_seq;
    }

    /** The message_seq of the next post-handshake message we expect to receive. */
    int getNextReceiveSeq()
    {
        return next_receive_seq;
    }

    /** How many NewSessionTicket messages have been received (and discarded). */
    int getNewSessionTicketCount()
    {
        return newSessionTicketCount;
    }

    /** How many KeyUpdate messages have been received. */
    int getKeyUpdateCount()
    {
        return keyUpdateCount;
    }

    /**
     * RFC 8446 4.6.3. Whether a received KeyUpdate asked for one in return and none has been sent since.
     * Read by the sending side, which owns the KeyUpdate state machine of RFC 9147 5.8.4 and is also the only
     * side that can apply section 8's override of this rule at the epoch limit.
     */
    boolean isKeyUpdatePendingSend()
    {
        return keyUpdatePendingSend;
    }

    /** Clear the RFC 8446 4.6.3 obligation, once the sending side has answered it. */
    void clearKeyUpdatePendingSend()
    {
        this.keyUpdatePendingSend = false;
    }
}
