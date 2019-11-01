package org.bouncycastle.tls.crypto;

import java.io.IOException;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsFatalAlert;

/**
 * The cipher for TLS_NULL_WITH_NULL_NULL.
 */
public class TlsNullNullCipher
    implements TlsCipher
{
    public static final TlsNullNullCipher INSTANCE = new TlsNullNullCipher();

    public int getCiphertextDecodeLimit(int plaintextLimit)
    {
        return plaintextLimit;
    }

    public int getCiphertextEncodeLimit(int plaintextLength, int plaintextLimit)
    {
        return plaintextLength;
    }

    public int getPlaintextLimit(int ciphertextLimit)
    {
        return ciphertextLimit;
    }

    public TlsEncodeResult encodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion, int headerAllocation,
        byte[] plaintext, int offset, int len) throws IOException
    {
        byte[] result = new byte[headerAllocation + len];
        System.arraycopy(plaintext, offset, result, headerAllocation, len);
        return new TlsEncodeResult(result, 0, result.length, contentType);
    }

    public TlsDecodeResult decodeCiphertext(long seqNo, short recordType, ProtocolVersion recordVersion,
        byte[] ciphertext, int offset, int len) throws IOException
    {
        return new TlsDecodeResult(ciphertext, offset, len, recordType);
    }

    public void rekeyDecoder() throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }
    
    public void rekeyEncoder() throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public boolean usesOpaqueRecordType()
    {
        return false;
    }
}
