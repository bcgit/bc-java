package org.bouncycastle.tls;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.tls.crypto.TlsHash;

/**
 * Base interface for an object that can calculate a handshake hash.
 */
public interface TlsHandshakeHash
    extends TlsHash
{
    void copyBufferTo(OutputStream output) throws IOException;

    void forceBuffering();

    void notifyPRFDetermined();

    void trackHashAlgorithm(short hashAlgorithm);

    void sealHashAlgorithms();

    TlsHandshakeHash stopTracking();

    TlsHash forkPRFHash();

    byte[] getFinalHash(short hashAlgorithm);
}
