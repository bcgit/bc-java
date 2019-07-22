package org.bouncycastle.crypto.tls;

import java.io.IOException;

/**
 * @deprecated Migrate to the (D)TLS API in org.bouncycastle.tls (bctls jar).
 */
public interface TlsCipher
{
    int getPlaintextLimit(int ciphertextLimit);

    byte[] encodePlaintext(long seqNo, short type, byte[] plaintext, int offset, int len)
        throws IOException;

    byte[] decodeCiphertext(long seqNo, short type, byte[] ciphertext, int offset, int len)
        throws IOException;
}
