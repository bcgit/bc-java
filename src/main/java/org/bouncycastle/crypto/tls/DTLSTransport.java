package org.bouncycastle.crypto.tls;

import java.io.IOException;

public class DTLSTransport implements DatagramTransport {

    private final DTLSRecordLayer recordLayer;
    private final TlsPeer peer;

    DTLSTransport(DTLSRecordLayer recordLayer, TlsPeer peer) {
        this.recordLayer = recordLayer;
        this.peer = peer;
    }

    public int getReceiveLimit() throws IOException {
        return recordLayer.getReceiveLimit();
    }

    public int getSendLimit() throws IOException {
        return recordLayer.getSendLimit();
    }

    public int receive(byte[] buf, int off, int len, int waitMillis) throws IOException {
        return recordLayer.receive(buf, off, len, waitMillis);
    }

    public void send(byte[] buf, int off, int len) throws IOException {
        recordLayer.send(buf, off, len);
    }

    public void close() throws IOException {
        recordLayer.close(peer);
    }
}
