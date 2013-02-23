package org.bouncycastle.crypto.tls;

import java.io.IOException;

public class DTLSTransport implements DatagramTransport {

    private final DatagramTransport transport;
    
    DTLSTransport(DatagramTransport transport) {
        this.transport = transport;
    }

    public int getReceiveLimit() throws IOException {
        return transport.getReceiveLimit();
    }

    public int getSendLimit() throws IOException {
        return transport.getSendLimit();
    }

    public int receive(byte[] buf, int off, int len, int waitMillis) throws IOException {
        return transport.receive(buf, off, len, waitMillis);
    }

    public void send(byte[] buf, int off, int len) throws IOException {
        transport.send(buf, off, len);
    }
}
