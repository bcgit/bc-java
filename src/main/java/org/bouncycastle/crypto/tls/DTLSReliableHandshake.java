package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.io.DigestOutputStream;

class DTLSReliableHandshake {

    private final static int MAX_RECEIVE_AHEAD = 10;

    private final DTLSRecordLayer recordLayer;

    private CombinedHash hash = new CombinedHash();
    private DigestOutputStream hashStream = new DigestOutputStream(hash);

    private Hashtable currentInboundFlight = new Hashtable();
    private Hashtable previousInboundFlight = null;
    private Vector outboundFlight = new Vector();
    private boolean sending = true;

    private int message_seq = 0, next_receive_seq = 0;

    DTLSReliableHandshake(DTLSRecordLayer transport) {
        this.recordLayer = transport;
    }

    byte[] getCurrentHash() {
        Digest copyOfHash = new CombinedHash(hash);
        byte[] result = new byte[copyOfHash.getDigestSize()];
        copyOfHash.doFinal(result, 0);
        return result;
    }

    void sendMessage(short msg_type, byte[] body) throws IOException {

        if (!sending) {
            checkInboundFlight();
            sending = true;
            outboundFlight.clear();
        }

        Message message = new Message(message_seq++, msg_type, body);

        outboundFlight.addElement(message);

        writeMessage(message);
        updateHandshakeMessagesDigest(message);
    }

    Message receiveMessage() throws IOException {

        if (sending) {
            sending = false;
            prepareInboundFlight();
        }

        // Check if we already have the next message waiting
        {
            DTLSReassembler next = (DTLSReassembler) currentInboundFlight.get(Integer
                .valueOf(next_receive_seq));
            if (next != null) {
                byte[] body = next.getBodyIfComplete();
                if (body != null) {
                    previousInboundFlight = null;
                    return updateHandshakeMessagesDigest(new Message(next_receive_seq++,
                        next.getType(), body));
                }
            }
        }

        byte[] buf = null;

        // TODO Check the conditions under which we should reset this
        int readTimeoutMillis = 1000;

        for (;;) {

            int receiveLimit = recordLayer.getReceiveLimit();
            if (buf == null || buf.length < receiveLimit) {
                buf = new byte[receiveLimit];
            }

            // TODO Handle records containing multiple handshake messages

            try {
                for (;;) {
                    int received = recordLayer.receive(buf, 0, receiveLimit, readTimeoutMillis);
                    if (received < 12) {
                        // TODO What kind of exception?
                        continue;
                    }
                    int fragment_length = TlsUtils.readUint24(buf, 9);
                    if (received != (fragment_length + 12)) {
                        // TODO What kind of exception?
                        continue;
                    }

                    int seq = TlsUtils.readUint16(buf, 4);
                    if (seq > (next_receive_seq + MAX_RECEIVE_AHEAD)) {
                        continue;
                    }

                    short msg_type = TlsUtils.readUint8(buf, 0);
                    int length = TlsUtils.readUint24(buf, 1);
                    int fragment_offset = TlsUtils.readUint24(buf, 6);

                    if (fragment_offset + fragment_length > length) {
                        // TODO What kind of exception?
                        continue;
                    }

                    if (seq < next_receive_seq) {
                        /*
                         * NOTE: If we receive the previous flight of incoming messages in full
                         * again, retransmit our last flight
                         */
                        if (previousInboundFlight != null) {
                            DTLSReassembler reassembler = (DTLSReassembler) previousInboundFlight
                                .get(Integer.valueOf(seq));
                            if (reassembler != null) {

                                reassembler.contributeFragment(msg_type, length, buf, 12,
                                    fragment_offset, fragment_length);

                                if (checkAll(previousInboundFlight)) {

                                    resendOutboundFlight();

                                    /*
                                     * TODO[DTLS] implementations SHOULD back off handshake packet
                                     * size during the retransmit backoff.
                                     */
                                    readTimeoutMillis = Math.min(readTimeoutMillis * 2, 60000);

                                    resetAll(previousInboundFlight);
                                }
                            }
                        }
                    } else {

                        DTLSReassembler reassembler = (DTLSReassembler) currentInboundFlight
                            .get(Integer.valueOf(seq));
                        if (reassembler == null) {
                            reassembler = new DTLSReassembler(msg_type, length);
                            currentInboundFlight.put(Integer.valueOf(seq), reassembler);
                        }

                        reassembler.contributeFragment(msg_type, length, buf, 12, fragment_offset,
                            fragment_length);

                        if (seq == next_receive_seq) {
                            byte[] body = reassembler.getBodyIfComplete();
                            if (body != null) {
                                previousInboundFlight = null;
                                return updateHandshakeMessagesDigest(new Message(
                                    next_receive_seq++, reassembler.getType(), body));
                            }
                        }
                    }
                }
            } catch (IOException e) {
                // NOTE: Assume this is a timeout for the moment
            }

            resendOutboundFlight();

            /*
             * TODO[DTLS] implementations SHOULD back off handshake packet size during the
             * retransmit backoff.
             */
            readTimeoutMillis = Math.min(readTimeoutMillis * 2, 60000);
        }
    }

    void finish() {
        if (sending) {
            // TODO Support case when this side sends the final handshake message
        }
        else {
            checkInboundFlight();
        }
    }

    void resetHandshakeMessagesDigest() {
        hash.reset();
    }

    /**
     * Check that there are no "extra" messages left in the current inbound flight
     */
    private void checkInboundFlight() {
        Enumeration e = currentInboundFlight.keys();
        while (e.hasMoreElements()) {
            Integer key = (Integer) e.nextElement();
            if (key.intValue() >= next_receive_seq) {
                // TODO Exception
            }
        }
    }

    private void prepareInboundFlight() {
        resetAll(currentInboundFlight);
        previousInboundFlight = currentInboundFlight;
        currentInboundFlight = new Hashtable();
    }

    private void resendOutboundFlight() throws IOException {
        recordLayer.resetWriteEpoch();
        for (int i = 0; i < outboundFlight.size(); ++i) {
            writeMessage((Message) outboundFlight.elementAt(i));
        }
    }

    private Message updateHandshakeMessagesDigest(Message message) throws IOException {
        if (message.getType() != HandshakeType.hello_request) {
            int length = message.getBody().length;
            TlsUtils.writeUint8(message.getType(), hashStream);
            TlsUtils.writeUint24(length, hashStream);
            TlsUtils.writeUint16(message.getSeq(), hashStream);
            TlsUtils.writeUint24(0, hashStream);
            TlsUtils.writeUint24(length, hashStream);
            hashStream.write(message.getBody(), 0, length);
        }
        return message;
    }

    private void writeMessage(Message message) throws IOException {

        int sendLimit = recordLayer.getSendLimit();
        int fragmentLimit = sendLimit - 12;

        // TODO Support a higher minimum fragment size?
        if (fragmentLimit < 1) {
            // TODO What kind of exception to throw?
        }

        int length = message.getBody().length;

        // NOTE: Must still send a fragment if body is empty
        int fragment_offset = 0;
        do {
            int fragment_length = Math.min(length - fragment_offset, fragmentLimit);
            writeHandshakeFragment(message, fragment_offset, fragment_length);
            fragment_offset += fragment_length;
        } while (fragment_offset < length);
    }

    private void writeHandshakeFragment(Message message, int fragment_offset, int fragment_length)
        throws IOException {

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        TlsUtils.writeUint8(message.getType(), buf);
        TlsUtils.writeUint24(message.getBody().length, buf);
        TlsUtils.writeUint16(message.getSeq(), buf);
        TlsUtils.writeUint24(fragment_offset, buf);
        TlsUtils.writeUint24(fragment_length, buf);
        buf.write(message.getBody(), fragment_offset, fragment_length);

        byte[] fragment = buf.toByteArray();

        recordLayer.send(fragment, 0, fragment.length);
    }

    private static boolean checkAll(Hashtable inboundFlight) {
        Enumeration e = inboundFlight.elements();
        while (e.hasMoreElements()) {
            if (((DTLSReassembler) e.nextElement()).getBodyIfComplete() == null)
                return false;
        }
        return true;
    }

    private static void resetAll(Hashtable inboundFlight) {
        Enumeration e = inboundFlight.elements();
        while (e.hasMoreElements()) {
            ((DTLSReassembler) e.nextElement()).reset();
        }
    }

    static class Message {

        private final int message_seq;
        private final short msg_type;
        private final byte[] body;

        private Message(int message_seq, short msg_type, byte[] body) {
            this.message_seq = message_seq;
            this.msg_type = msg_type;
            this.body = body;
        }

        public int getSeq() {
            return message_seq;
        }

        public short getType() {
            return msg_type;
        }

        public byte[] getBody() {
            return body;
        }
    }
}
