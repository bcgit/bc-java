package org.bouncycastle.crypto.tls;

interface DTLSHandshakeRetransmit {
    void receivedHandshakeRecord(int epoch, byte[] buf, int off, int len);
}
