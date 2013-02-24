package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

class DTLSReliableHandshake {

    private final static int MAX_RECEIVE_AHEAD = 10;

    private final DatagramTransport transport;

    private Hashtable incomingQueue = new Hashtable();
    private Vector flight = new Vector();
    private boolean sending = true;

    private int message_seq = 0, next_receive_seq = 0;

    DTLSReliableHandshake(DatagramTransport transport) {
        this.transport = transport;
    }

    void sendMessage(short msg_type, byte[] body) throws IOException {

        if (!sending) {
            sending = true;
            flight.clear();
        }

        Message message = new Message(message_seq++, msg_type, body);

        flight.add(message);

        writeMessage(message);
    }

    Message receiveMessage() throws IOException {

        sending = false;

        // Check if we already have the next message waiting
        {
            DTLSReassembler next = (DTLSReassembler)incomingQueue.get(Integer.valueOf(next_receive_seq));
            if (next != null)
            {
                byte[] body = next.getBodyIfComplete();
                if (body != null) {
                    incomingQueue.remove(Integer.valueOf(next_receive_seq));
                    return new Message(next_receive_seq++, next.getType(), body);
                }
            }
        }

        byte[] buf = null;
        int readTimeoutMillis = 1000;

        for (;;) {

            int receiveLimit = transport.getReceiveLimit();
            if (buf == null || buf.length < receiveLimit) {
                buf = new byte[receiveLimit];
            }

            try {
                for (;;) {
                    int received = transport.receive(buf, 0, receiveLimit, readTimeoutMillis);
                    if (received < 12) {
                        // TODO What kind of exception?
                    }
                    int fragment_length = TlsUtils.readUint24(buf, 9);
                    if (received != (fragment_length + 12)) {
                        // TODO What kind of exception?
                    }

                    int seq = TlsUtils.readUint16(buf, 5);
                    if (seq < next_receive_seq || seq > (next_receive_seq + MAX_RECEIVE_AHEAD)) {
                        continue;
                    }

                    short msg_type = TlsUtils.readUint8(buf, 0);
                    int length = TlsUtils.readUint24(buf, 1);
                    int fragment_offset = TlsUtils.readUint24(buf, 6);

                    // TODO Add fast path for next_receive_seq and for single-fragment messages

                    DTLSReassembler reassembler = (DTLSReassembler)incomingQueue.get(Integer.valueOf(seq));
                    if (reassembler == null) {
                        reassembler = new DTLSReassembler(msg_type, length);
                        incomingQueue.put(Integer.valueOf(seq), reassembler);
                    }

                    reassembler.contributeFragment(msg_type, length, buf, 12, fragment_offset, fragment_length);

                    if (seq == next_receive_seq) {
                        byte[] body = reassembler.getBodyIfComplete();
                        if (body != null) {
                            incomingQueue.remove(Integer.valueOf(next_receive_seq));
                            return new Message(next_receive_seq++, reassembler.getType(), body);
                        }
                    }
                }
            } catch (IOException e) {
                // NOTE: Assume this is a timeout for the moment
            }

            resendFlight();

            readTimeoutMillis = Math.min(readTimeoutMillis * 2, 60000);
        }
    }

    void finish()
    {
        sending = true;
        flight.clear();

        if (!incomingQueue.isEmpty()) {
            // TODO Throw exception - unexpected message!
        }
    }

    private void resendFlight() throws IOException {
        for (int i = 0; i < flight.size(); ++i) {
            writeMessage((Message) flight.elementAt(i));
        }
    }

    private void writeMessage(Message message) throws IOException {

        int sendLimit = transport.getSendLimit();
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

        transport.send(fragment, 0, fragment.length);
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
