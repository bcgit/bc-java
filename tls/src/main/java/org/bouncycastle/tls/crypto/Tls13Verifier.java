package org.bouncycastle.tls.crypto;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Base interface for a TLS 1.3 signature verifier.
 */
public interface Tls13Verifier
{
    OutputStream getOutputStream() throws IOException;

    boolean verifySignature(byte[] signature) throws IOException;
}
