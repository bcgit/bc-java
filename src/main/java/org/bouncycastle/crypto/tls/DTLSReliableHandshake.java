package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Vector;

class DTLSReliableHandshake {

    private final DatagramTransport transport;

    private Vector flight = new Vector();
    private boolean sending = true;

    private int message_seq = 0, next_receive_seq = 0;

    DTLSReliableHandshake(DatagramTransport transport) {
        this.transport = transport;
    }

    void sendMessage(short msg_type, byte[] body) throws IOException {

        if (!sending)
        {
            sending = true;
            flight.clear();
        }

        Message message = new Message(message_seq++, msg_type, body);

        flight.add(message);

        writeMessage(message);
    }

    Message receiveMessage() throws IOException {

        sending = false;

        byte[] buf = null;
        int readTimeoutMillis = 1000;

        for (;;)
        {
            int receiveLimit = transport.getReceiveLimit();
            if (buf == null || buf.length < receiveLimit) {
                buf = new byte[receiveLimit];
            }

            try {
                int length = transport.receive(buf, 0, receiveLimit, readTimeoutMillis);

                // TODO We have received a fragment, need to assemble them until we get a full message
            }
            catch (IOException e) {
                // NOTE: Assume this is a timeout for the moment
            }

            resendFlight();

            readTimeoutMillis = Math.min(readTimeoutMillis * 2, 60000);
        }
    }

    private void resendFlight() throws IOException
    {
        for (int i = 0; i < flight.size(); ++i) {
            writeMessage((Message)flight.elementAt(i));
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
        do
        {
            int fragment_length = Math.min(length - fragment_offset, fragmentLimit);
            writeHandshakeFragment(message, fragment_offset, fragment_length);
            fragment_offset += fragment_length;
        }
        while (fragment_offset < length);
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
