package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public final class CertificateVerify
{
    private final int algorithm;
    private final byte[] signature;

    public CertificateVerify(int algorithm, byte[] signature)
    {
        if (!TlsUtils.isValidUint16(algorithm))
        {
            throw new IllegalArgumentException("'algorithm'");
        }
        if (signature == null)
        {
            throw new NullPointerException("'signature' cannot be null");
        }

        this.algorithm = algorithm;
        this.signature = signature;
    }

    /**
     * @return the algorithm (a signature scheme)
     * @see SignatureScheme
     */
    public int getAlgorithm()
    {
        return algorithm;
    }

    public byte[] getSignature()
    {
        return signature;
    }

    /**
     * Encode this {@link CertificateVerify} to an {@link OutputStream}.
     * 
     * @param output
     *            the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output) throws IOException
    {
        TlsUtils.writeUint16(algorithm, output);
        TlsUtils.writeOpaque16(signature, output);
    }

    /**
     * Parse a {@link CertificateVerify} from an {@link InputStream}.
     * 
     * @param context
     *            the {@link TlsContext} of the current connection.
     * @param input
     *            the {@link InputStream} to parse from.
     * @return a {@link CertificateVerify} object.
     * @throws IOException
     */
    public static CertificateVerify parse(TlsContext context, InputStream input) throws IOException
    {
        if (!TlsUtils.isTLSv13(context))
        {
            throw new IllegalStateException();
        }

        int algorithm = TlsUtils.readUint16(input);
        byte[] signature = TlsUtils.readOpaque16(input);
        return new CertificateVerify(algorithm, signature);
    }
}
