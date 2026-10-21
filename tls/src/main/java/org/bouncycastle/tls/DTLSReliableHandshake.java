package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.util.Integers;

class DTLSReliableHandshake
{
    static final int MESSAGE_HEADER_LENGTH = 12;

    // RFC 8446 4: msg_type (uint8) and length (uint24), which is what a DTLS 1.3 transcript hashes
    static final int TLS_MESSAGE_HEADER_LENGTH = 4;

    private static final int MAX_RECEIVE_AHEAD = 16;
    private static final int MAX_RESEND_MILLIS = 60000;

    static ByteArrayInputStream receiveClientHelloMessage(byte[] msg, int msgOff, int msgLen) throws IOException
    {
        // TODO Support the possibility of a fragmented ClientHello datagram

        if (msgLen < MESSAGE_HEADER_LENGTH)
        {
            return null;
        }

        short msgType = TlsUtils.readUint8(msg, msgOff);
        if (HandshakeType.client_hello != msgType)
        {
            return null;
        }

        int length = TlsUtils.readUint24(msg, msgOff + 1);
        if (msgLen != MESSAGE_HEADER_LENGTH + length)
        {
            return null;
        }

        // TODO Consider stricter HelloVerifyRequest-related checks
//        int messageSeq = TlsUtils.readUint16(msg, msgOff + 4);
//        if (messageSeq > 1)
//        {
//            return null;
//        }

        int fragmentOffset = TlsUtils.readUint24(msg, msgOff + 6);
        if (0 != fragmentOffset)
        {
            return null;
        }

        int fragmentLength = TlsUtils.readUint24(msg, msgOff + 9);
        if (length != fragmentLength)
        {
            return null;
        }

        return new ByteArrayInputStream(msg, msgOff + MESSAGE_HEADER_LENGTH, length);
    }

    static void sendHelloVerifyRequest(DatagramSender sender, long recordSeq, byte[] cookie) throws IOException
    {
        TlsUtils.checkUint8(cookie.length);

        int length = 3 + cookie.length;

        byte[] message = new byte[MESSAGE_HEADER_LENGTH + length];
        TlsUtils.writeUint8(HandshakeType.hello_verify_request, message, 0);
        TlsUtils.writeUint24(length, message, 1);
//        TlsUtils.writeUint16(0, message, 4);
//        TlsUtils.writeUint24(0, message, 6);
        TlsUtils.writeUint24(length, message, 9);

        // HelloVerifyRequest fields
        TlsUtils.writeVersion(ProtocolVersion.DTLSv10, message, MESSAGE_HEADER_LENGTH + 0);
        TlsUtils.writeOpaque8(cookie, message, MESSAGE_HEADER_LENGTH + 2);

        DTLSRecordLayer.sendHelloVerifyRequestRecord(sender, recordSeq, message);
    }

    /*
     * No 'final' modifiers so that it works in earlier JDKs
     */
    private TlsContext context;
    private DTLSRecordLayer recordLayer;
    private Timeout handshakeTimeout;

    private TlsHandshakeHash handshakeHash;

    /*
     * RFC 9147 5.2. "In DTLS 1.3, the message transcript is computed over the original TLS 1.3-style
     * Handshake messages without the message_seq, fragment_offset, and fragment_length values." DTLS 1.2
     * hashes the full 12-byte DTLS header instead.
     *
     * The negotiated version is not known when the ClientHello is hashed, nor (for a client) when the
     * ServerHello is, so messages are held here until it is and only then encoded. Choosing the encoding
     * per message as it arrives would hash the ClientHello in one form and everything after it in the
     * other; both peers would do that identically, so no handshake between two of these would ever fail
     * and the transcript would still be wrong on the wire.
     */
    private Vector undecidedTranscript = new Vector();
    private boolean transcriptDecided = false;
    private boolean transcriptDTLS13 = false;

    private Hashtable currentInboundFlight = new Hashtable();
    private Hashtable previousInboundFlight = null;
    private Vector outboundFlight = new Vector();
    private DTLS13FlightTracker flightTracker = new DTLS13FlightTracker();
    private boolean flightOpen = false;

    private int initialResendMillis;
    private int resendMillis = -1;
    private Timeout resendTimeout = null;

    private int next_send_seq = 0, next_receive_seq = 0;

    /*
     * RFC 9147 7.1. The record numbers of the handshake records of the current inbound flight that were
     * processed or buffered, and the two triggers for acknowledging them.
     */
    private Vector ackRecordNumbers = new Vector();
    private Timeout ackTimeout = null;
    private boolean ackRequested = false;

    private int maxHandshakeMessageSize;

    DTLSReliableHandshake(TlsContext context, DTLSRecordLayer transport, int timeoutMillis, int initialResendMillis,
        DTLSRequest request, int maxHandshakeMessageSize)
    {
        long currentTimeMillis = System.currentTimeMillis();

        this.context = context;
        this.recordLayer = transport;
        this.handshakeHash = new DeferredHash(context);
        this.handshakeTimeout = Timeout.forWaitMillis(timeoutMillis, currentTimeMillis);
        this.initialResendMillis = initialResendMillis;
        this.maxHandshakeMessageSize = maxHandshakeMessageSize;

        if (null != request)
        {
            resendMillis = initialResendMillis;
            resendTimeout = new Timeout(resendMillis, currentTimeMillis);

            long recordSeq = request.getRecordSeq();
            int messageSeq = request.getMessageSeq();
            byte[] message = request.getMessage();

            recordLayer.resetAfterHelloVerifyRequestServer(recordSeq);

            // Simulate a previous flight consisting of the request ClientHello
            DTLSReassembler reassembler = new DTLSReassembler(HandshakeType.client_hello, message.length - MESSAGE_HEADER_LENGTH);
            currentInboundFlight.put(Integers.valueOf(messageSeq), reassembler);

            // We sent HelloVerifyRequest with (message) sequence number 0
            next_send_seq = 1;
            next_receive_seq = messageSeq + 1;

            /*
             * NOTE: Deferred like any other message, since the negotiated version is not known yet. The
             * DTLS 1.2 encoding of this reproduces 'message' exactly: DTLSVerifier only accepts an
             * unfragmented ClientHello, so its fragment_offset is 0 and its fragment_length is its length.
             */
            byte[] clientHelloBody = TlsUtils.copyOfRangeExact(message, MESSAGE_HEADER_LENGTH, message.length);
            undecidedTranscript.addElement(new Message(messageSeq, HandshakeType.client_hello, clientHelloBody));
        }

        recordLayer.setAckListener(new DTLSAckListener()
        {
            public void receivedAck(Vector recordNumbers)
            {
                // RFC 9147 7.2. Retire the acknowledged fragments; retransmission consults the tracker.
                flightTracker.acknowledge(recordNumbers);
            }
        });
    }

    void resetAfterHelloVerifyRequestClient()
    {
        currentInboundFlight = new Hashtable();
        previousInboundFlight = null;
        outboundFlight = new Vector();
        flightTracker.reset();

        resendMillis = -1;
        resendTimeout = null;

        // We're waiting for ServerHello, always with (message) sequence number 1
        next_receive_seq = 1;

        undecidedTranscript.removeAllElements();
        transcriptDecided = false;
        transcriptDTLS13 = false;

        handshakeHash.reset();
    }

    TlsHandshakeHash getHandshakeHash()
    {
        // NOTE: Nothing may read the transcript while any message is still held undecided
        checkTranscriptDecided();

        /*
         * A transcript that is still undecided has written nothing to the digest yet, so handing the hash
         * out here would silently yield a transcript missing every buffered message. That must never
         * happen: fail loudly instead of computing a verify_data or a signature over the wrong bytes.
         */
        if (!transcriptDecided && !undecidedTranscript.isEmpty())
        {
            throw new IllegalStateException("DTLS handshake transcript requested before the negotiated "
                + "version was known, with " + undecidedTranscript.size() + " message(s) still buffered");
        }

        return handshakeHash;
    }

    void prepareToFinish()
    {
        checkTranscriptDecided();

        handshakeHash.stopTracking();
    }

    void sendMessage(short msg_type, byte[] body)
        throws IOException
    {
        TlsUtils.checkUint24(body.length);

        /*
         * draft-ietf-tls-rfc9147bis: message_seq is a uint16 and "MUST NOT wrap"; writeUint16 would
         * silently truncate and reuse the sequence number of an earlier message.
         */
        if (next_send_seq > 0xFFFF)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        if (null != resendTimeout)
        {
            checkInboundFlight();

            resendMillis = -1;
            resendTimeout = null;

            outboundFlight.removeAllElements();
            flightTracker.reset();
        }

        beginOutboundFlight();

        Message message = new Message(next_send_seq++, msg_type, body);

        outboundFlight.addElement(message);

        writeMessage(message);
        updateHandshakeMessagesDigest(message);
    }

    Message receiveMessage()
        throws IOException
    {
        Message message = implReceiveMessage();
        updateHandshakeMessagesDigest(message);
        return message;
    }

    byte[] receiveMessageBody(short msg_type)
        throws IOException
    {
        Message message = implReceiveMessage();
        if (message.getType() != msg_type)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        updateHandshakeMessagesDigest(message);
        return message.getBody();
    }

    /**
     * Receive the next message without digesting it, leaving that to a later call to
     * {@link #updateHandshakeMessagesDigest(Message)}. For a message whose type is not known in advance but
     * which may need something else hashed ahead of it: RFC 8446 4.4.1's synthetic "message_hash" message
     * replaces the first ClientHello in the transcript before a HelloRetryRequest is hashed after it, and a
     * HelloRetryRequest is only recognisable once its body has been read.
     */
    Message receiveMessageDelayedDigest()
        throws IOException
    {
        return implReceiveMessage();
    }

    Message receiveMessageDelayedDigest(short msg_type)
        throws IOException
    {
        Message message = implReceiveMessage();
        if (message.getType() != msg_type)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        return message;
    }

    void updateHandshakeMessagesDigest(Message message)
        throws IOException
    {
        switch (message.getType())
        {
        case HandshakeType.hello_request:
        case HandshakeType.hello_verify_request:
        case HandshakeType.key_update:
            return;

        // TODO[dtls13] Not included in the transcript for (D)TLS 1.3+
        case HandshakeType.new_session_ticket:
        default:
            break;
        }

        if (!transcriptDecided)
        {
            undecidedTranscript.addElement(message);

            // NOTE: Flushes this message too, once the negotiated version is known
            checkTranscriptDecided();
            return;
        }

        writeTranscriptMessage(message);
    }

    /**
     * Encode the pending messages as soon as the negotiated version says which header form the transcript
     * uses. Until then nothing has been written to the digest, and a caller that reads the transcript before
     * that point would see an empty one; every caller goes through {@link #getHandshakeHash()}, which calls
     * this first, and on both sides the version is known before the transcript is ever read.
     */
    private void checkTranscriptDecided()
    {
        if (transcriptDecided)
        {
            return;
        }

        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        if (null == securityParameters)
        {
            return;
        }

        ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();
        if (null == negotiatedVersion)
        {
            return;
        }

        this.transcriptDTLS13 = TlsUtils.isTLSv13(negotiatedVersion);
        this.transcriptDecided = true;

        int count = undecidedTranscript.size();
        for (int i = 0; i < count; ++i)
        {
            writeTranscriptMessage((Message)undecidedTranscript.elementAt(i));
        }
        undecidedTranscript.removeAllElements();
    }

    private void writeTranscriptMessage(Message message)
    {
        short msg_type = message.getType();
        byte[] body = message.getBody();

        byte[] buf;
        if (transcriptDTLS13)
        {
            /*
             * RFC 9147 5.2. The TLS 1.3-style header only: msg_type and the body length.
             */
            buf = new byte[TLS_MESSAGE_HEADER_LENGTH];
            TlsUtils.writeUint8(msg_type, buf, 0);
            TlsUtils.writeUint24(body.length, buf, 1);
        }
        else
        {
            buf = new byte[MESSAGE_HEADER_LENGTH];
            TlsUtils.writeUint8(msg_type, buf, 0);
            TlsUtils.writeUint24(body.length, buf, 1);
            TlsUtils.writeUint16(message.getSeq(), buf, 4);
            TlsUtils.writeUint24(0, buf, 6);
            TlsUtils.writeUint24(body.length, buf, 9);
        }

        handshakeHash.update(buf, 0, buf.length);
        handshakeHash.update(body, 0, body.length);
    }

    void finish()
        throws IOException
    {
        endOutboundFlight();

        DTLSHandshakeRetransmit retransmit = null;
        if (null != resendTimeout)
        {
            checkInboundFlight();

            if (recordLayer.isDTLS13() && !ackRecordNumbers.isEmpty())
            {
                /*
                 * RFC 9147 7.1. We have just received the peer's final flight. No flight of ours follows it,
                 * so nothing acknowledges it implicitly and it must be acknowledged explicitly.
                 */
                final Vector finalFlightAck = ackRecordNumbers;
                final Hashtable finalFlight = summarizeFlight(currentInboundFlight);

                /*
                 * RFC 9147 5.8.1. The epoch that flight was protected under, taken from the record layer -
                 * which is about to retain exactly that epoch for reading - rather than assumed to be the
                 * handshake epoch's current number.
                 */
                final int finalFlightEpoch = recordLayer.getRetiredEpoch();

                sendPendingAck();

                /*
                 * RFC 9147 5.8.1. If that ACK is lost the peer retransmits its final flight, and the answer
                 * is another ACK of the same records - not a retransmitted flight, since no flight of ours
                 * follows. The record layer retains the handshake epoch so the retransmission can still be
                 * read, and the ACK goes out at the current (application) write epoch, which the peer has by
                 * now installed for reading.
                 *
                 * Only a record that plausibly carries that flight is answered. Anything else arriving with a
                 * handshake content type - at worst an unauthenticated record, since the record layer also
                 * retains epoch 0 on the side that needs to read it - would otherwise draw an ACK out of us.
                 */
                retransmit = new DTLSHandshakeRetransmit()
                {
                    public void receivedHandshakeRecord(int epoch, byte[] buf, int off, int len)
                        throws IOException
                    {
                        if (matchesFlight(finalFlight, finalFlightEpoch, epoch, buf, off, len))
                        {
                            sendAck(finalFlightAck);
                        }
                    }
                };
            }
        }
        else
        {
            prepareInboundFlight(null);

            if (previousInboundFlight != null)
            {
                /*
                 * RFC 6347 4.2.4. In addition, for at least twice the default MSL defined for [TCP],
                 * when in the FINISHED state, the node that transmits the last flight (the server in an
                 * ordinary handshake or the client in a resumed handshake) MUST respond to a retransmit
                 * of the peer's last flight with a retransmit of the last flight.
                 */
                retransmit = new DTLSHandshakeRetransmit()
                {
                    public void receivedHandshakeRecord(int epoch, byte[] buf, int off, int len)
                        throws IOException
                    {
                        processRecord(0, epoch, buf, off, len);
                    }
                };
            }
        }

        // RFC 9147 7. Post-handshake ACKs belong to the post-handshake state machines, not this flight tracker.
        recordLayer.setAckListener(null);

        recordLayer.handshakeSuccessful(retransmit);
    }

    static int backOff(int timeoutMillis)
    {
        /*
         * TODO[DTLS] implementations SHOULD back off handshake packet size during the
         * retransmit backoff.
         */
        return Math.min(timeoutMillis * 2, MAX_RESEND_MILLIS);
    }

    /**
     * The message_seq, msg_type and length of each complete message of a flight, which is all that is needed
     * to recognise a retransmission of it. The reassemblers themselves are deliberately not retained: their
     * bodies are the largest thing the handshake holds, and this summary outlives the handshake.
     */
    static Hashtable summarizeFlight(Hashtable inboundFlight)
    {
        Hashtable summary = new Hashtable();

        Enumeration e = inboundFlight.keys();
        while (e.hasMoreElements())
        {
            Integer key = (Integer)e.nextElement();
            DTLSReassembler reassembler = (DTLSReassembler)inboundFlight.get(key);
            byte[] body = reassembler.getBodyIfComplete();
            if (null != body)
            {
                summary.put(key, new int[]{ reassembler.getMsgType(), body.length });
            }
        }

        return summary;
    }

    /**
     * RFC 9147 5.8.1. Whether a handshake record that arrived after the handshake completed plausibly carries
     * a retransmission of the flight summarized by {@link #summarizeFlight(Hashtable)}, which is the only
     * thing a retransmitted ACK answers.
     * <p>
     * The framing checks are those {@link #processRecord(int, int, byte[], int, int)} makes, which is the
     * model for how much gating is enough: the epoch must be the one that flight was protected under, and
     * every fragment in the record must belong to a message that flight was made of. Without this, any record
     * whose decoded content type is handshake would draw an ACK, including an unauthenticated one on the side
     * that retains epoch 0 for reading.
     * </p>
     */
    static boolean matchesFlight(Hashtable flight, int flightEpoch, int epoch, byte[] buf, int off, int len)
    {
        /*
         * RFC 9147 6.1. The flight this answers is the peer's final flight, and 'flightEpoch' is the epoch it
         * was protected under - the handshake epoch, which the record layer has retained for reading. A
         * record at any other epoch carries none of it, the unauthenticated epoch 0 included; a flightEpoch
         * of -1 means no epoch was retired, so there is nothing to recognise.
         */
        if (flightEpoch < 0 || flightEpoch != epoch || len < MESSAGE_HEADER_LENGTH)
        {
            return false;
        }

        while (len >= MESSAGE_HEADER_LENGTH)
        {
            short msg_type = TlsUtils.readUint8(buf, off + 0);
            int length = TlsUtils.readUint24(buf, off + 1);
            int message_seq = TlsUtils.readUint16(buf, off + 4);
            int fragment_offset = TlsUtils.readUint24(buf, off + 6);
            int fragment_length = TlsUtils.readUint24(buf, off + 9);

            int message_length = MESSAGE_HEADER_LENGTH + fragment_length;
            if (len < message_length || fragment_offset + fragment_length > length)
            {
                // NOTE: Truncated or malformed - not something the peer sent us before
                return false;
            }

            int[] expected = (int[])flight.get(Integers.valueOf(message_seq));
            if (null == expected || expected[0] != msg_type || expected[1] != length)
            {
                return false;
            }

            off += message_length;
            len -= message_length;
        }

        return true;
    }

    /**
     * Check that there are no "extra" messages left in the current inbound flight
     */
    private void checkInboundFlight()
    {
        Enumeration e = currentInboundFlight.keys();
        while (e.hasMoreElements())
        {
            Integer key = (Integer)e.nextElement();
            if (key.intValue() >= next_receive_seq)
            {
                // TODO Should this be considered an error?
            }
        }
    }

    private Message getPendingMessage() throws IOException
    {
        DTLSReassembler next = (DTLSReassembler)currentInboundFlight.get(Integers.valueOf(next_receive_seq));
        if (next != null)
        {
            byte[] body = next.getBodyIfComplete();
            if (body != null)
            {
                previousInboundFlight = null;
                return new Message(next_receive_seq++, next.getMsgType(), body);
            }
        }
        return null;
    }

    private Message implReceiveMessage()
        throws IOException
    {
        endOutboundFlight();

        long currentTimeMillis = System.currentTimeMillis();

        if (null == resendTimeout)
        {
            resendMillis = initialResendMillis;
            resendTimeout = new Timeout(resendMillis, currentTimeMillis);

            prepareInboundFlight(new Hashtable());
        }

        byte[] buf = null;

        for (;;)
        {
            if (recordLayer.isClosed())
            {
                throw new TlsFatalAlert(AlertDescription.user_canceled);
            }

            if (recordLayer.isDTLS13()
                && (ackRequested || Timeout.hasExpired(ackTimeout, currentTimeMillis)))
            {
                sendPendingAck();
            }

            Message pending = getPendingMessage();
            if (pending != null)
            {
                return pending;
            }

            if (Timeout.hasExpired(handshakeTimeout, currentTimeMillis))
            {
                throw new TlsTimeoutException("Handshake timed out");
            }

            int waitMillis = Timeout.getWaitMillis(handshakeTimeout, currentTimeMillis);
            waitMillis = Timeout.constrainWaitMillis(waitMillis, resendTimeout, currentTimeMillis);
            waitMillis = Timeout.constrainWaitMillis(waitMillis, ackTimeout, currentTimeMillis);

            // NOTE: Ensure a finite wait, of at least 1ms
            if (waitMillis < 1)
            {
                waitMillis = 1;
            }

            int receiveLimit = recordLayer.getReceiveLimit();
            if (buf == null || buf.length < receiveLimit)
            {
                buf = new byte[receiveLimit];
            }

            int received = recordLayer.receive(buf, 0, receiveLimit, waitMillis);
            if (received < 0)
            {
                resendOutboundFlight();
            }
            else
            {
                boolean accepted = processRecord(MAX_RECEIVE_AHEAD, recordLayer.getLastReceivedEpoch(), buf, 0,
                    received);

                if (accepted && recordLayer.isDTLS13())
                {
                    /*
                     * RFC 9147 7.1. Only a record that was processed or buffered may be acknowledged.
                     */
                    DTLSRecordNumber recordNumber = recordLayer.getLastReceivedRecordNumber();
                    if (null != recordNumber && ackRecordNumbers.size() < maxAckRecordNumbers())
                    {
                        ackRecordNumbers.addElement(recordNumber);
                    }

                    if (null == ackTimeout)
                    {
                        /*
                         * RFC 9147 7.1. Part of a flight has arrived: ACK it if the rest does not follow
                         * within a quarter of the current retransmit timer.
                         */
                        ackTimeout = new Timeout(Math.max(1, resendMillis / 4), System.currentTimeMillis());
                    }
                }
            }

            currentTimeMillis = System.currentTimeMillis();
        }
    }

    private void prepareInboundFlight(Hashtable nextFlight)
    {
        /*
         * RFC 9147 7.1. During the handshake an ACK covers only the flight being received, so the
         * accumulated record numbers and both triggers are dropped at every flight boundary.
         */
        ackRecordNumbers = new Vector();
        ackTimeout = null;
        ackRequested = false;

        resetAll(currentInboundFlight);
        previousInboundFlight = currentInboundFlight;
        currentInboundFlight = nextFlight;
    }

    /**
     * @return true only if every message carried by the record was processed or buffered, which is the
     *         RFC 9147 7.1 condition for including the record's number in an ACK. A message discarded
     *         because a previous copy had been received still counts as processed, and RFC 9147 7.1 says so
     *         explicitly; a message that was rejected does not, and acknowledging its record would tell the
     *         peer not to retransmit something we dropped.
     */
    private boolean processRecord(int windowSize, int epoch, byte[] buf, int off, int len) throws IOException
    {
        boolean accepted = false;
        boolean dropped = false;
        boolean checkPreviousFlight = false;

        while (len >= MESSAGE_HEADER_LENGTH)
        {
            int fragment_length = TlsUtils.readUint24(buf, off + 9);
            int message_length = fragment_length + MESSAGE_HEADER_LENGTH;
            if (len < message_length)
            {
                // NOTE: Truncated message - ignore it
                dropped = true;
                break;
            }

            int length = TlsUtils.readUint24(buf, off + 1);
            int fragment_offset = TlsUtils.readUint24(buf, off + 6);
            if (fragment_offset + fragment_length > length)
            {
                // NOTE: Malformed fragment - ignore it and the rest of the record
                dropped = true;
                break;
            }

            if (length > maxHandshakeMessageSize)
            {
                // NOTE: Declared message length exceeds the configured maximum - ignore it (and
                // the rest of the record) rather than committing a reassembly buffer of that size.
                // The reassembler is sized from this attacker-controlled length before any
                // signature/Finished verification, so an unbounded value is a memory-exhaustion DoS.
                dropped = true;
                break;
            }

            /*
             * NOTE: This very simple epoch check will only work until we want to support
             * renegotiation (and we're not likely to do that anyway).
             */
            short msg_type = TlsUtils.readUint8(buf, off + 0);

            int expectedEpoch;
            if (recordLayer.isDTLS13())
            {
                /*
                 * RFC 9147 6.1. Epoch 0 carries the unencrypted ClientHello, ServerHello and
                 * HelloRetryRequest; every other message of the main handshake is protected under the
                 * handshake traffic keys at epoch 2. Post-handshake messages arrive at epoch 3 and above
                 * and are not part of this flight.
                 */
                expectedEpoch = (HandshakeType.client_hello == msg_type || HandshakeType.server_hello == msg_type)
                    ? 0 : 2;
            }
            else
            {
                expectedEpoch = msg_type == HandshakeType.finished ? 1 : 0;
            }

            if (epoch != expectedEpoch)
            {
                dropped = true;
                break;
            }

            int message_seq = TlsUtils.readUint16(buf, off + 4);
            if (message_seq >= (next_receive_seq + windowSize))
            {
                // NOTE: Too far ahead - ignore
                dropped = true;
            }
            else if (message_seq >= next_receive_seq)
            {
                DTLSReassembler reassembler = (DTLSReassembler)currentInboundFlight.get(Integers.valueOf(message_seq));
                if (reassembler == null)
                {
                    reassembler = new DTLSReassembler(msg_type, length);
                    currentInboundFlight.put(Integers.valueOf(message_seq), reassembler);
                }

                int nextExpectedOffset = reassembler.getNextExpectedOffset();
                if (nextExpectedOffset >= 0 && fragment_offset != nextExpectedOffset)
                {
                    /*
                     * RFC 9147 7.1. This is not the next piece of the message, whether because an earlier
                     * fragment was lost or because this one is a fresh message beginning past its own start;
                     * either way something was lost, so ACK what we have.
                     *
                     * A negative next expected offset means the message is already complete, so the fragment
                     * is a duplicate rather than evidence of loss. It is still accumulated below (RFC 9147
                     * 7.1 acknowledges records whose messages were discarded as duplicates), but forcing an
                     * ACK for it would let a peer replaying one fragment draw one ACK per copy; the quarter
                     * timer batches it instead.
                     */
                    ackRequested = true;
                }

                if (message_seq != next_receive_seq)
                {
                    // RFC 9147 7.1. A message ahead of the next expected one is a sign of loss; ACK what we have.
                    ackRequested = true;
                }

                if (reassembler.contributeFragment(msg_type, length, buf, off + MESSAGE_HEADER_LENGTH,
                        fragment_offset, fragment_length)
                    || reassembler.acceptsFragment(msg_type, length, fragment_offset, fragment_length))
                {
                    /*
                     * RFC 9147 7.1. Contributed, or discarded because a previous copy had been received;
                     * both count as processed, so the record carrying it may be acknowledged.
                     */
                    accepted = true;
                }
                else
                {
                    dropped = true;
                }
            }
            else if (previousInboundFlight != null)
            {
                /*
                 * NOTE: If we receive the previous flight of incoming messages in full again,
                 * retransmit our last flight
                 */

                DTLSReassembler reassembler = (DTLSReassembler)previousInboundFlight.get(Integers.valueOf(message_seq));
                if (reassembler != null)
                {
                    if (reassembler.contributeFragment(msg_type, length, buf, off + MESSAGE_HEADER_LENGTH,
                            fragment_offset, fragment_length)
                        || reassembler.acceptsFragment(msg_type, length, fragment_offset, fragment_length))
                    {
                        accepted = true;
                    }
                    else
                    {
                        dropped = true;
                    }

                    checkPreviousFlight = true;
                }
                else
                {
                    // NOTE: Already delivered, so a duplicate, which RFC 9147 7.1 counts as processed
                    accepted = true;
                }
            }
            else
            {
                // NOTE: Already delivered, so a duplicate, which RFC 9147 7.1 counts as processed
                accepted = true;
            }

            off += message_length;
            len -= message_length;
        }

        if (checkPreviousFlight && checkAll(previousInboundFlight))
        {
            resendOutboundFlight();
            resetAll(previousInboundFlight);
        }

        return accepted && !dropped;
    }

    /**
     * RFC 9147 7.1: "The ACK message ... SHOULD include as many received records as fit into the ACK
     * record", and when there is not room for all of them "the implementation SHOULD favor including
     * records which have not yet been acknowledged".
     * <p>
     * So the bound on an ACK is what a datagram will carry, not a fixed count: any count large enough to
     * be useful puts the body over a typical path MTU, and an ACK that is itself fragmented or dropped
     * cannot do the one thing it is for, which is to stop the peer retransmitting. The record layer's send
     * limit is the plaintext body it can carry, so the ACK's own uint16 length prefix comes off it and what
     * is left divides by the 16 bytes of one RecordNumber. It is computed per ACK rather than cached,
     * because the send limit moves with the write epoch's cipher overhead and with the path MTU. The floor
     * of one keeps an ACK possible whatever the limit says.
     * </p>
     */
    private int maxAckRecordNumbers() throws IOException
    {
        /*
         * A floor of zero rather than one: on an implausibly small send limit an empty ACK is still legal
         * (RFC 9147 7.1) and still shortcuts the peer's retransmit timer, whereas one record number would
         * not fit and the record would exceed the limit.
         */
        return Math.max(0, (recordLayer.getSendLimit() - 2) / DTLSAck.RECORD_NUMBER_LENGTH);
    }

    private void sendPendingAck() throws IOException
    {
        ackRequested = false;
        ackTimeout = null;

        sendAck(ackRecordNumbers);
    }

    private void sendAck(Vector recordNumbers) throws IOException
    {
        Vector toSend = recordNumbers;

        int maxRecordNumbers = maxAckRecordNumbers();
        if (toSend.size() > maxRecordNumbers)
        {
            /*
             * RFC 9147 7.1 asks that the records favoured be the ones not yet acknowledged. The receive
             * side does not track which of these already went out in an earlier ACK of this flight, so the
             * earliest entries are kept instead: being the oldest, they are the ones the peer is most
             * likely to still be retransmitting. Omitting the rest is safe - the only cost is a
             * retransmission of the records left out.
             */
            Vector trimmed = new Vector(maxRecordNumbers);
            for (int i = 0; i < maxRecordNumbers; ++i)
            {
                trimmed.addElement(toSend.elementAt(i));
            }
            toSend = trimmed;
        }

        // RFC 9147 7.1. An ACK with no record numbers is legal and shortcuts the peer's retransmit timer.
        recordLayer.sendAck(toSend);
    }

    private void resendOutboundFlight()
        throws IOException
    {
        if (!recordLayer.isDTLS13())
        {
            /*
             * DTLS 1.2 only: this restores the write epoch to the epoch of the flight being retransmitted.
             * DTLS 1.3 never registers the legacy retransmit, and resetting here could move the write epoch
             * back from a pending epoch that only the write direction has switched to.
             */
            recordLayer.resetWriteEpoch();
        }

        beginOutboundFlight();

        if (recordLayer.isDTLS13() && !flightTracker.isEmpty())
        {
            /*
             * RFC 9147 5.8.1 and 7.2. Retransmit only the fragments that have not been acknowledged; a
             * record that appeared in any ACK counts as delivered. Once every fragment of the flight has
             * been acknowledged, getOutstanding() is empty and this loop writes and flushes nothing,
             * which is exactly RFC 9147 7.2's requirement to cancel all retransmission of that flight.
             */
            Vector outstanding = flightTracker.getOutstanding();
            for (int i = 0; i < outstanding.size(); ++i)
            {
                DTLS13FlightTracker.Fragment fragment = (DTLS13FlightTracker.Fragment)outstanding.elementAt(i);
                Message message = getOutboundMessage(fragment.getMessageSeq());
                if (null != message)
                {
                    /*
                     * RFC 9147 5.8.1. Each fragment goes back out at the epoch it was first sent at: a DTLS 1.3
                     * flight straddles an epoch change, and after the handshake has completed the write epoch
                     * has moved on to keys the peer cannot read while it is still retransmitting.
                     */
                    retransmitHandshakeFragment(message, fragment.getFragmentOffset(),
                        fragment.getFragmentLength(), fragment.getEpoch());
                }
            }
        }
        else
        {
            for (int i = 0; i < outboundFlight.size(); ++i)
            {
                writeMessage((Message)outboundFlight.elementAt(i));
            }
        }

        endOutboundFlight();

        resendMillis = backOff(resendMillis);
        resendTimeout = new Timeout(resendMillis);
    }

    private Message getOutboundMessage(int messageSeq)
    {
        for (int i = 0; i < outboundFlight.size(); ++i)
        {
            Message message = (Message)outboundFlight.elementAt(i);
            if (message.getSeq() == messageSeq)
            {
                return message;
            }
        }
        return null;
    }

    private void beginOutboundFlight() throws IOException
    {
        if (!flightOpen)
        {
            // github #1487. Pack this flight's records into as few datagrams as the MTU allows.
            recordLayer.beginFlight();
            flightOpen = true;
        }
    }

    private void endOutboundFlight() throws IOException
    {
        if (flightOpen)
        {
            recordLayer.endFlight();
            flightOpen = false;
        }
    }

    /** For the reliable-handshake tests: close the current outbound flight. */
    void endFlightForTest() throws IOException
    {
        endOutboundFlight();
    }

    /** For the reliable-handshake tests: deliver an ACK as the record layer's listener would. */
    void acknowledgeForTest(Vector recordNumbers)
    {
        flightTracker.acknowledge(recordNumbers);
    }

    /** For the reliable-handshake tests: position the send counter, e.g. at the uint16 limit. */
    void setNextSendSeqForTest(int nextSendSeq)
    {
        next_send_seq = nextSendSeq;
    }

    /** For the reliable-handshake tests: drive the retransmission path directly. */
    void resendOutboundFlightForTest() throws IOException
    {
        resendOutboundFlight();
    }

    private void writeMessage(Message message)
        throws IOException
    {
        int sendLimit = recordLayer.getSendLimit();
        int fragmentLimit = sendLimit - MESSAGE_HEADER_LENGTH;

        // TODO Support a higher minimum fragment size?
        if (fragmentLimit < 1)
        {
            // TODO Should we be throwing an exception here?
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        int length = message.getBody().length;

        // NOTE: Must still send a fragment if body is empty
        int fragment_offset = 0;
        do
        {
            int fragment_length = Math.min(length - fragment_offset, fragmentLimit);
            writeHandshakeFragment(message, fragment_offset, fragment_length);
            fragment_offset += fragment_length;
        }
        while (fragment_offset < length);
    }

    private void writeHandshakeFragment(Message message, int fragment_offset, int fragment_length)
        throws IOException
    {
        implWriteHandshakeFragment(message, fragment_offset, fragment_length, -1);
    }

    private void retransmitHandshakeFragment(Message message, int fragment_offset, int fragment_length, int epoch)
        throws IOException
    {
        if (epoch < 0)
        {
            /*
             * A tracked fragment always has an epoch: DTLS13FlightTracker.register records one from the record
             * number that carried the fragment, and implWriteHandshakeFragment only registers a fragment when
             * the record layer returned a record number. A fragment without one would be retransmitted at the
             * current write epoch, which is the very defect the per-fragment epoch exists to prevent, so it is
             * raised rather than written.
             */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        implWriteHandshakeFragment(message, fragment_offset, fragment_length, epoch);
    }

    /**
     * @param epoch the epoch to send at, or a negative value to use the record layer's current write epoch.
     */
    private void implWriteHandshakeFragment(Message message, int fragment_offset, int fragment_length, int epoch)
        throws IOException
    {
        RecordLayerBuffer fragment = new RecordLayerBuffer(MESSAGE_HEADER_LENGTH + fragment_length);
        TlsUtils.writeUint8(message.getType(), fragment);
        TlsUtils.writeUint24(message.getBody().length, fragment);
        TlsUtils.writeUint16(message.getSeq(), fragment);
        TlsUtils.writeUint24(fragment_offset, fragment);
        TlsUtils.writeUint24(fragment_length, fragment);
        fragment.write(message.getBody(), fragment_offset, fragment_length);

        DTLSRecordNumber recordNumber = epoch < 0
            ? fragment.sendToRecordLayer(recordLayer)
            : fragment.sendToRecordLayerAtEpoch(recordLayer, epoch);

        if (null != recordNumber)
        {
            /*
             * RFC 9147 7.2. Remember which record carried this fragment so an ACK can retire it.
             *
             * Registered for both versions rather than only when isDTLS13(): a DTLS 1.3 flight can straddle
             * the point at which the record layer switches to the 1.3 format, because initPendingEpoch sets
             * that flag only after ServerHello has been written. A fragment written before the switch would
             * otherwise be absent from the tracker and silently omitted from the retransmitted flight, which
             * could then never complete. Only the consumption of the tracker is gated on isDTLS13(), so
             * DTLS 1.2 pays for the entries and never reads them.
             */
            flightTracker.register(recordNumber, message.getSeq(), fragment_offset, fragment_length);
        }
    }

    private static boolean checkAll(Hashtable inboundFlight)
    {
        Enumeration e = inboundFlight.elements();
        while (e.hasMoreElements())
        {
            if (((DTLSReassembler)e.nextElement()).getBodyIfComplete() == null)
            {
                return false;
            }
        }
        return true;
    }

    private static void resetAll(Hashtable inboundFlight)
    {
        Enumeration e = inboundFlight.elements();
        while (e.hasMoreElements())
        {
            ((DTLSReassembler)e.nextElement()).reset();
        }
    }

    static class Message
    {
        private final int message_seq;
        private final short msg_type;
        private final byte[] body;

        Message(int message_seq, short msg_type, byte[] body)
        {
            this.message_seq = message_seq;
            this.msg_type = msg_type;
            this.body = body;
        }

        public int getSeq()
        {
            return message_seq;
        }

        public short getType()
        {
            return msg_type;
        }

        public byte[] getBody()
        {
            return body;
        }
    }

    static class RecordLayerBuffer extends ByteArrayOutputStream
    {
        RecordLayerBuffer(int size)
        {
            super(size);
        }

        DTLSRecordNumber sendToRecordLayer(DTLSRecordLayer recordLayer) throws IOException
        {
            DTLSRecordNumber recordNumber = recordLayer.sendReturningRecordNumber(buf, 0, count);
            buf = null;
            return recordNumber;
        }

        DTLSRecordNumber sendToRecordLayerAtEpoch(DTLSRecordLayer recordLayer, int epoch) throws IOException
        {
            DTLSRecordNumber recordNumber = recordLayer.sendHandshakeRecordAtEpoch(epoch, buf, 0, count);
            buf = null;
            return recordNumber;
        }
    }
}
