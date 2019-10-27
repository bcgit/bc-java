package org.bouncycastle.tls.crypto;

import java.io.IOException;

import org.bouncycastle.tls.ProtocolVersion;

/**
 * The cipher for TLS_NULL_WITH_NULL_NULL.
 */
public class TlsNullNullCipher
    implements TlsCipher
{
    public static final TlsNullNullCipher INSTANCE = new TlsNullNullCipher();

    public int getCiphertextLimit(int plaintextLimit)
    {
        return plaintextLimit;
    }

    public int getPlaintextLimit(int ciphertextLimit)
    {
        return ciphertextLimit;
    }

    public byte[] encodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion, int headerAllocation,
        byte[] plaintext, int offset, int len) throws IOException
    {
        byte[] result = new byte[headerAllocation + len];
        System.arraycopy(plaintext, offset, result, headerAllocation, len);
        return result;
    }

    public TlsDecodeResult decodeCiphertext(long seqNo, short contentType, ProtocolVersion recordVersion,
        byte[] ciphertext, int offset, int len) throws IOException
    {
        return new TlsDecodeResult(ciphertext, offset, len, contentType);
    }
}
