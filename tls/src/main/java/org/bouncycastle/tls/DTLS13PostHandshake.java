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
     * Only the KeyUpdate state machine registers into it: post-handshake messages are single-flight (5.8.4),
     * so at most one message is ever outstanding and {@code isComplete} is exactly "our KeyUpdate has been
     * acknowledged".
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

    /**
     * RFC 9147 5.8.4 and 8. The KeyUpdate we have sent and not yet seen acknowledged, retained so that it can
     * be retransmitted byte for byte, and doubling as the latch: section 5.8.4 forbids sending a KeyUpdate
     * while an earlier one is unacknowledged, and section 8 forbids sending anything at all under the new
     * epoch until then. Null means no key update of ours is in flight.
     * <p>
     * There is no second copy of this state anywhere. The derived write epoch it is waiting for lives in the
     * record layer (see {@code derivePendingWriteEpoch}), and the fragments it is waiting to have
     * acknowledged live in {@code flightTracker}; this field is what ties the two together and what says the
     * state machine is running.
     * </p>
     */
    private byte[] keyUpdateMessage = null;

    /**
     * RFC 9147 8. The epoch the outstanding KeyUpdate was sent under, which is the epoch it must be
     * retransmitted under: it is the only epoch the peer can read until it has processed the KeyUpdate, and
     * it is the epoch we are still writing at, since section 8 will not let us move until it is acknowledged.
     */
    private int keyUpdateEpoch = -1;

    /** The message_seq of the outstanding KeyUpdate, for registering each retransmission of it. */
    private int keyUpdateMessageSeq = -1;

    private int keyUpdateResendMillis = -1;
    private Timeout keyUpdateResendTimeout = null;

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
    public synchronized void receivedAck(Vector recordNumbers)
    {
        flightTracker.acknowledge(recordNumbers);

        /*
         * RFC 9147 8. "implementations MUST NOT send records with the new keys ... until the previous
         * KeyUpdate has been acknowledged". This is that acknowledgement, and it is the ONLY thing that
         * installs the new write epoch.
         *
         * It is emphatically not the peer's decryption of anything, and the receiving half's release trigger
         * is not this. The two halves of section 8 have different triggers: the sender may not write at its
         * new epoch until its KeyUpdate is ACKed, while the receiver may not release the pre-update keys
         * until a record has decrypted at the new epoch. An ACK proves the peer parsed a record; it says
         * nothing about what the peer has begun sending.
         */
        if (null != keyUpdateMessage && flightTracker.isComplete())
        {
            recordLayer.installPendingWriteEpoch();

            this.keyUpdateMessage = null;
            this.keyUpdateEpoch = -1;
            this.keyUpdateMessageSeq = -1;
            this.keyUpdateResendMillis = -1;
            this.keyUpdateResendTimeout = null;

            flightTracker.reset();
        }
    }

    /**
     * RFC 9147 8 and RFC 8446 4.6.3 and 5.5. Start a key update if one is owed, called from the record
     * layer's send path before a record goes out.
     * <p>
     * Two things can owe one: an obligation recorded by a received {@code update_requested}, and the write
     * epoch's sequence number reaching the automatic threshold. Neither is acted on while a KeyUpdate of ours
     * is still unacknowledged - section 5.8.4 forbids a second one, and there would be nowhere to put the
     * derived epoch in any case.
     * </p>
     * <p>
     * <b>A deliberate deviation from RFC 8446, disclosed here because it is the only one in this
     * implementation.</b> Two MUSTs collide in that first case and they cannot both be honoured. RFC 8446
     * 4.6.3: a peer that receives {@code update_requested} MUST send a KeyUpdate of its own "prior to sending
     * its next Application Data record". RFC 9147 5.8.4: an implementation MUST NOT send a KeyUpdate "if an
     * earlier message of the same type has not yet been acknowledged". When an {@code update_requested}
     * arrives while our own KeyUpdate is outstanding, honouring 8446 means breaking 9147, and the only way to
     * break neither is to stop sending application data until the outstanding update clears. So 9147 is
     * followed: the obligation is DEFERRED past application data - the latch above holds it - and discharged
     * on the first send after the outstanding KeyUpdate has been acknowledged.
     * </p>
     * <p>
     * 9147 wins on three grounds. It is the DTLS specification constraining a TLS rule it inherits. Its rule
     * is load-bearing: only two epoch bits are on the wire (RFC 9147 4.2.2), so a second unacknowledged
     * KeyUpdate makes the receiver's epoch reconstruction ambiguous, whereas 8446's rule is timeliness
     * hygiene - the answer is late, not absent. And the third option, blocking application data until the
     * outstanding update clears, would be a self-inflicted stall on the data path in response to a
     * peer-controlled message. The deferral is bounded by our own retransmit state machine (5.8.4), which is
     * already driving that KeyUpdate to an acknowledgement.
     * </p>
     * The record this was called for is unaffected: it still goes out at the current write epoch, because
     * section 8 will not let the write epoch move until the KeyUpdate is acknowledged.
     */
    synchronized void checkKeyUpdateBeforeSend() throws IOException
    {
        if (null != keyUpdateMessage)
        {
            return;
        }

        if (!keyUpdatePendingSend && !recordLayer.needsKeyUpdate())
        {
            return;
        }

        /*
         * RFC 8446 4.6.3. A KeyUpdate sent to discharge an 'update_requested' carries
         * 'update_not_requested', or the two peers would answer each other forever.
         */
        sendKeyUpdate(KeyUpdateRequest.update_not_requested);
    }

    /**
     * RFC 9147 5.8.4 and 8. Send a KeyUpdate and start the state machine that waits for its acknowledgement.
     * <p>
     * The order of the three steps is fixed. The new write epoch is derived FIRST, because
     * {@code update13TrafficSecretLocal} destroys the secret the current write epoch was keyed from, so the
     * new epoch can only be built at this moment - and because a derivation that fails must fail before a
     * KeyUpdate has been put on the wire announcing an update we then could not perform. The message goes out
     * SECOND, at the old epoch, which is the only epoch the peer can read. The state machine is armed LAST,
     * and within that the latch - {@code keyUpdateMessage} - is assigned after the flight tracker it speaks
     * for, so that nothing is left latched if any earlier step throws and nothing observes the latch set over
     * a tracker that does not yet describe this message.
     * </p>
     *
     * @throws IllegalStateException if a KeyUpdate of ours is already awaiting acknowledgement. RFC 9147
     *             5.8.4: "implementations MUST NOT send KeyUpdate ... messages if an earlier message of the
     *             same type has not yet been acknowledged."
     */
    synchronized void sendKeyUpdate(short requestUpdate) throws IOException
    {
        if (null != keyUpdateMessage)
        {
            throw new IllegalStateException("a KeyUpdate is already awaiting acknowledgement");
        }

        int epoch = recordLayer.getWriteEpoch();
        int message_seq = next_send_seq;

        byte[] message = new byte[DTLSReliableHandshake.MESSAGE_HEADER_LENGTH + 1];
        TlsUtils.writeUint8(HandshakeType.key_update, message, 0);
        TlsUtils.writeUint24(1, message, 1);
        TlsUtils.writeUint16(message_seq, message, 4);
        TlsUtils.writeUint24(0, message, 6);
        TlsUtils.writeUint24(1, message, 9);
        TlsUtils.writeUint8(requestUpdate, message, 12);

        recordLayer.deriveNextWriteEpoch();

        DTLSRecordNumber recordNumber = recordLayer.sendHandshakeRecordAtEpoch(epoch, message, 0,
            message.length);

        next_send_seq += 1;

        /*
         * The flight tracker is reset and registered BEFORE 'keyUpdateMessage', which is the latch: while the
         * latch is set, receivedAck acts on a complete tracker by installing the new write epoch, so the
         * tracker must already describe this KeyUpdate's fragment by the time the latch says one is
         * outstanding. Ordering it this way makes that true by construction rather than by the (true, but
         * two-step and easily invalidated) argument that isComplete() returns false on an empty tracker and
         * the tracker happens to be empty here.
         */
        flightTracker.reset();
        flightTracker.register(recordNumber, message_seq, 0, 1);

        this.keyUpdateEpoch = epoch;
        this.keyUpdateMessageSeq = message_seq;
        this.keyUpdateResendMillis = recordLayer.getHandshakeResendTimeMillis();
        this.keyUpdateResendTimeout = new Timeout(keyUpdateResendMillis);

        // Last: the latch. Nothing above it leaves the state machine running if it throws.
        this.keyUpdateMessage = message;

        /*
         * RFC 8446 4.6.3. Whatever prompted this one, it discharges any obligation to answer an
         * 'update_requested': the peer asked for a key update and is getting one.
         */
        this.keyUpdatePendingSend = false;
    }

    /**
     * RFC 9147 5.8.4. Drive the sending state machines, which "reduce to waiting for an ACK and
     * retransmitting the original message". Called from the record layer's receive loop.
     */
    synchronized void checkTimeouts(long currentTimeMillis) throws IOException
    {
        if (null == keyUpdateMessage || !Timeout.hasExpired(keyUpdateResendTimeout, currentTimeMillis))
        {
            return;
        }

        this.keyUpdateResendMillis = DTLSReliableHandshake.backOff(keyUpdateResendMillis);
        this.keyUpdateResendTimeout = new Timeout(keyUpdateResendMillis, currentTimeMillis);

        /*
         * At the epoch it was first sent under, not the current write epoch - which is the same epoch for as
         * long as this message is outstanding (RFC 9147 8), so this is a statement of intent rather than a
         * correction. The peer cannot read anything above it until it has processed this very message.
         */
        DTLSRecordNumber recordNumber = recordLayer.sendHandshakeRecordAtEpoch(keyUpdateEpoch,
            keyUpdateMessage, 0, keyUpdateMessage.length);

        // The same fragment under a new record number: either record being acknowledged retires it
        flightTracker.register(recordNumber, keyUpdateMessageSeq, 0, 1);
    }

    /**
     * The retransmit timeout of the outstanding KeyUpdate, or null when none is outstanding. Read by the
     * record layer's receive loop, which must not block past it - a peer waiting for an ACK it will never get
     * because we never woke up to resend is the failure this exists to prevent.
     */
    synchronized Timeout getResendTimeout()
    {
        return keyUpdateResendTimeout;
    }

    /** @return true while a KeyUpdate of ours is awaiting acknowledgement. */
    synchronized boolean isKeyUpdateOutstanding()
    {
        return null != keyUpdateMessage;
    }

    /** @return the epoch the outstanding KeyUpdate was sent at, or -1 when none is outstanding. */
    synchronized int getKeyUpdateEpoch()
    {
        return keyUpdateEpoch;
    }

    /**
     * Bring the KeyUpdate retransmit timeout forward so that the next receive expires it through its own code
     * path, instead of a test having to wait out the peer's configured resend interval.
     */
    synchronized void expireKeyUpdateResendTimeoutForTest()
    {
        if (null != keyUpdateResendTimeout)
        {
            this.keyUpdateResendTimeout = new Timeout(0);
        }
    }

    /**
     * Handle one deprotected handshake record received after the handshake completed.
     *
     * @param epoch the epoch the record was protected under, as resolved by the record layer.
     */
    synchronized void receivedHandshakeRecord(int epoch, byte[] buf, int off, int len)
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
             *
             * NOTE: "prior to sending its next Application Data record" is quoted above as the rule, and on
             * one path it is knowingly NOT honoured. If our own KeyUpdate is outstanding when this arrives,
             * RFC 9147 5.8.4 forbids sending a second one, so the obligation is deferred PAST application
             * data until the outstanding one is acknowledged. That is a deliberate reading of 9147 over 8446,
             * not an oversight; checkKeyUpdateBeforeSend carries the grounds, and
             * DTLS13KeyUpdateTest.testAnUpdateRequestedIsDeferredWhileOurOwnKeyUpdateIsOutstanding exercises
             * it.
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
    synchronized DTLS13FlightTracker getFlightTracker()
    {
        return flightTracker;
    }

    /** The message_seq of the next post-handshake message we expect to receive. */
    synchronized int getNextReceiveSeq()
    {
        return next_receive_seq;
    }

    /** How many NewSessionTicket messages have been received (and discarded). */
    synchronized int getNewSessionTicketCount()
    {
        return newSessionTicketCount;
    }

    /** How many KeyUpdate messages have been received. */
    synchronized int getKeyUpdateCount()
    {
        return keyUpdateCount;
    }

    /**
     * RFC 8446 4.6.3. Whether a received KeyUpdate asked for one in return and none has been sent since.
     * Read by the sending side, which owns the KeyUpdate state machine of RFC 9147 5.8.4 and is also the only
     * side that can apply section 8's override of this rule at the epoch limit.
     */
    synchronized boolean isKeyUpdatePendingSend()
    {
        return keyUpdatePendingSend;
    }

    /** Clear the RFC 8446 4.6.3 obligation, once the sending side has answered it. */
    synchronized void clearKeyUpdatePendingSend()
    {
        this.keyUpdatePendingSend = false;
    }
}
