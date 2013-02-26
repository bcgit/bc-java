package org.bouncycastle.crypto.tls.test;

import java.io.IOException;
import java.io.PrintStream;

import org.bouncycastle.crypto.tls.DatagramTransport;

public class LoggingDatagramTransport implements DatagramTransport {

    private static final String HEX_CHARS = "0123456789ABCDEF";

    private final DatagramTransport transport;
    private final PrintStream output;

    public LoggingDatagramTransport(DatagramTransport transport, PrintStream output) {
        this.transport = transport;
        this.output = output;
    }

    public int getReceiveLimit() throws IOException {
        return transport.getReceiveLimit();
    }

    public int getSendLimit() throws IOException {
        return transport.getSendLimit();
    }

    public int receive(byte[] buf, int off, int len, int waitMillis) throws IOException {
        int length = transport.receive(buf, off, len, waitMillis);
        if (length >= 0) {
            dumpDatagram("Received", buf, off, length);
        }
        return length;
    }

    public void send(byte[] buf, int off, int len) throws IOException {
        dumpDatagram("Sent", buf, off, len);
        transport.send(buf, off, len);
    }

    private void dumpDatagram(String verb, byte[] buf, int off, int len) throws IOException {
        output.print(verb + " " + len + " byte datagram:");
        for (int pos = 0; pos < len; ++pos) {
            if (pos % 16 == 0) {
                output.println();
                output.print("    ");
            }
            else if (pos % 16 == 8) {
                output.print('-');
            }
            else {
                output.print(' ');
            }
            int val = buf[off + pos] & 0xFF;
            output.print(HEX_CHARS.charAt(val >> 4));
            output.print(HEX_CHARS.charAt(val & 0xF));
        }
        output.println();
    }
}
