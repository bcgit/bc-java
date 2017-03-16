package org.bouncycastle.tls.crypto;

import java.io.IOException;

import org.bouncycastle.util.Arrays;

/**
 * The cipher for TLS_NULL_WITH_NULL_NULL.
 */
public class TlsNullNullCipher
    implements TlsCipher
{
    public int getPlaintextLimit(int ciphertextLimit)
    {
        return ciphertextLimit;
    }

    public byte[] encodePlaintext(long seqNo, short type, byte[] plaintext, int offset, int len)
        throws IOException
    {
        return Arrays.copyOfRange(plaintext, offset, offset + len);
    }

    public byte[] decodeCiphertext(long seqNo, short type, byte[] ciphertext, int offset, int len)
        throws IOException
    {
        return Arrays.copyOfRange(ciphertext, offset, offset + len);
    }
}
