package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.util.Integers;

class DTLSReliableHandshake
{
    private static final int MAX_RECEIVE_AHEAD = 16;
    private static final int MESSAGE_HEADER_LENGTH = 12;

    static final int INITIAL_RESEND_MILLIS = 1000;
    private static final int MAX_RESEND_MILLIS = 60000;

    static DTLSRequest readClientRequest(byte[] data, int dataOff, int dataLen, OutputStream dtlsOutput)
        throws IOException
    {
        // TODO Support the possibility of a fragmented ClientHello datagram

        byte[] message = DTLSRecordLayer.receiveClientHelloRecord(data, dataOff, dataLen);
        if (null == message || message.length < MESSAGE_HEADER_LENGTH)
        {
            return null;
        }

        long recordSeq = TlsUtils.readUint48(data, dataOff + 5);

        short msgType = TlsUtils.readUint8(message, 0);
        if (HandshakeType.client_hello != msgType)
        {
            return null;
        }

        int length = TlsUtils.readUint24(message, 1);
        if (message.length != MESSAGE_HEADER_LENGTH + length)
        {
            return null;
        }

        // TODO Consider stricter HelloVerifyRequest-related checks
//        int messageSeq = TlsUtils.readUint16(message, 4);
//        if (messageSeq > 1)
//        {
//            return null;
//        }

        int fragmentOffset = TlsUtils.readUint24(message, 6);
        if (0 != fragmentOffset)
        {
            return null;
        }

        int fragmentLength = TlsUtils.readUint24(message, 9);
        if (length != fragmentLength)
        {
            return null;
        }

        ClientHello clientHello = ClientHello.parse(new ByteArrayInputStream(message, MESSAGE_HEADER_LENGTH, length), dtlsOutput);

        return new DTLSRequest(recordSeq, message, clientHello);
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
    private DTLSRecordLayer recordLayer;
    private Timeout handshakeTimeout;

    private TlsHandshakeHash handshakeHash;

    private Hashtable currentInboundFlight = new Hashtable();
    private Hashtable previousInboundFlight = null;
    private Vector outboundFlight = new Vector();

    private int resendMillis = -1;
    private Timeout resendTimeout = null;

    private int next_send_seq = 0, next_receive_seq = 0;

    DTLSReliableHandshake(TlsContext context, DTLSRecordLayer transport, int timeoutMillis, DTLSRequest request)
    {
        this.recordLayer = transport;
        this.handshakeHash = new DeferredHash(context);
        this.handshakeTimeout = Timeout.forWaitMillis(timeoutMillis);

        if (null != request)
        {
            resendMillis = INITIAL_RESEND_MILLIS;
            resendTimeout = new Timeout(resendMillis);

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

            handshakeHash.update(message, 0, message.length);
        }
    }

    void resetAfterHelloVerifyRequestClient()
    {
        currentInboundFlight = new Hashtable();
        previousInboundFlight = null;
        outboundFlight = new Vector();

        resendMillis = -1;
        resendTimeout = null;

        // We're waiting for ServerHello, always with (message) sequence number 1
        next_receive_seq = 1;

        handshakeHash.reset();
    }

    TlsHandshakeHash getHandshakeHash()
    {
        return handshakeHash;
    }

    TlsHandshakeHash prepareToFinish()
    {
        TlsHandshakeHash result = handshakeHash;
        this.handshakeHash = handshakeHash.stopTracking();
        return result;
    }

    void sendMessage(short msg_type, byte[] body)
        throws IOException
    {
        TlsUtils.checkUint24(body.length);

        if (null != resendTimeout)
        {
            checkInboundFlight();

            resendMillis = -1;
            resendTimeout = null;

            outboundFlight.removeAllElements();
        }

        Message message = new Message(next_send_seq++, msg_type, body);

        outboundFlight.addElement(message);

        writeMessage(message);
        updateHandshakeMessagesDigest(message);
    }

    byte[] receiveMessageBody(short msg_type)
        throws IOException
    {
        Message message = receiveMessage();
        if (message.getType() != msg_type)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        return message.getBody();
    }

    Message receiveMessage()
        throws IOException
    {
        long currentTimeMillis = System.currentTimeMillis();

        if (null == resendTimeout)
        {
            resendMillis = INITIAL_RESEND_MILLIS;
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
                processRecord(MAX_RECEIVE_AHEAD, recordLayer.getReadEpoch(), buf, 0, received);
            }

            currentTimeMillis = System.currentTimeMillis();
        }
    }

    void finish()
    {
        DTLSHandshakeRetransmit retransmit = null;
        if (null != resendTimeout)
        {
            checkInboundFlight();
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
                return updateHandshakeMessagesDigest(new Message(next_receive_seq++, next.getMsgType(), body));
            }
        }
        return null;
    }

    private void prepareInboundFlight(Hashtable nextFlight)
    {
        resetAll(currentInboundFlight);
        previousInboundFlight = currentInboundFlight;
        currentInboundFlight = nextFlight;
    }

    private void processRecord(int windowSize, int epoch, byte[] buf, int off, int len) throws IOException
    {
        boolean checkPreviousFlight = false;

        while (len >= MESSAGE_HEADER_LENGTH)
        {
            int fragment_length = TlsUtils.readUint24(buf, off + 9);
            int message_length = fragment_length + MESSAGE_HEADER_LENGTH;
            if (len < message_length)
            {
                // NOTE: Truncated message - ignore it
                break;
            }

            int length = TlsUtils.readUint24(buf, off + 1);
            int fragment_offset = TlsUtils.readUint24(buf, off + 6);
            if (fragment_offset + fragment_length > length)
            {
                // NOTE: Malformed fragment - ignore it and the rest of the record
                break;
            }

            /*
             * NOTE: This very simple epoch check will only work until we want to support
             * renegotiation (and we're not likely to do that anyway).
             */
            short msg_type = TlsUtils.readUint8(buf, off + 0);
            int expectedEpoch = msg_type == HandshakeType.finished ? 1 : 0;
            if (epoch != expectedEpoch)
            {
                break;
            }

            int message_seq = TlsUtils.readUint16(buf, off + 4);
            if (message_seq >= (next_receive_seq + windowSize))
            {
                // NOTE: Too far ahead - ignore
            }
            else if (message_seq >= next_receive_seq)
            {
                DTLSReassembler reassembler = (DTLSReassembler)currentInboundFlight.get(Integers.valueOf(message_seq));
                if (reassembler == null)
                {
                    reassembler = new DTLSReassembler(msg_type, length);
                    currentInboundFlight.put(Integers.valueOf(message_seq), reassembler);
                }

                reassembler.contributeFragment(msg_type, length, buf, off + MESSAGE_HEADER_LENGTH, fragment_offset,
                    fragment_length);
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
                    reassembler.contributeFragment(msg_type, length, buf, off + MESSAGE_HEADER_LENGTH, fragment_offset,
                        fragment_length);
                    checkPreviousFlight = true;
                }
            }

            off += message_length;
            len -= message_length;
        }

        if (checkPreviousFlight && checkAll(previousInboundFlight))
        {
            resendOutboundFlight();
            resetAll(previousInboundFlight);
        }
    }

    private void resendOutboundFlight()
        throws IOException
    {
        recordLayer.resetWriteEpoch();
        for (int i = 0; i < outboundFlight.size(); ++i)
        {
            writeMessage((Message)outboundFlight.elementAt(i));
        }

        resendMillis = backOff(resendMillis);
        resendTimeout = new Timeout(resendMillis);
    }

    private Message updateHandshakeMessagesDigest(Message message)
        throws IOException
    {
        short msg_type = message.getType();
        switch (msg_type)
        {
        case HandshakeType.hello_request:
        case HandshakeType.hello_verify_request:
        case HandshakeType.key_update:
        case HandshakeType.new_session_ticket:
            break;

        default:
        {
            byte[] body = message.getBody();
            byte[] buf = new byte[MESSAGE_HEADER_LENGTH];
            TlsUtils.writeUint8(msg_type, buf, 0);
            TlsUtils.writeUint24(body.length, buf, 1);
            TlsUtils.writeUint16(message.getSeq(), buf, 4);
            TlsUtils.writeUint24(0, buf, 6);
            TlsUtils.writeUint24(body.length, buf, 9);
            handshakeHash.update(buf, 0, buf.length);
            handshakeHash.update(body, 0, body.length);
        }
        }

        return message;
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
        RecordLayerBuffer fragment = new RecordLayerBuffer(MESSAGE_HEADER_LENGTH + fragment_length);
        TlsUtils.writeUint8(message.getType(), fragment);
        TlsUtils.writeUint24(message.getBody().length, fragment);
        TlsUtils.writeUint16(message.getSeq(), fragment);
        TlsUtils.writeUint24(fragment_offset, fragment);
        TlsUtils.writeUint24(fragment_length, fragment);
        fragment.write(message.getBody(), fragment_offset, fragment_length);

        fragment.sendToRecordLayer(recordLayer);
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

        private Message(int message_seq, short msg_type, byte[] body)
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

        void sendToRecordLayer(DTLSRecordLayer recordLayer) throws IOException
        {
            recordLayer.send(buf, 0, count);
            buf = null;
        }
    }
}
