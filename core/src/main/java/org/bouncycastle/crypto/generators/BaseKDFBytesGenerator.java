package org.bouncycastle.crypto.generators;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.DigestDerivationFunction;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.ISO18033KDFParameters;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.util.Pack;

/**
 * Basic KDF generator for derived keys and ivs as defined by IEEE P1363a/ISO
 * 18033 <br>
 * This implementation is based on ISO 18033/P1363a.
 */
public class BaseKDFBytesGenerator
    implements DigestDerivationFunction
{
    private int    counterStart;
    private Digest digest;
    private byte[] shared;
    private byte[] iv;

    /**
     * Construct a KDF Parameters generator.
     * <p>
     * 
     * @param counterStart
     *            value of counter.
     * @param digest
     *            the digest to be used as the source of derived keys.
     */
    protected BaseKDFBytesGenerator(int counterStart, Digest digest)
    {
        this.counterStart = counterStart;
        this.digest = digest;
    }

    public void init(DerivationParameters param)
    {
        if (param instanceof KDFParameters)
        {
            KDFParameters p = (KDFParameters)param;

            shared = p.getSharedSecret();
            iv = p.getIV();
        }
        else if (param instanceof ISO18033KDFParameters)
        {
            ISO18033KDFParameters p = (ISO18033KDFParameters)param;

            shared = p.getSeed();
            iv = null;
        }
        else
        {
            throw new IllegalArgumentException("KDF parameters required for generator");
        }
    }

    /**
     * return the underlying digest.
     */
    public Digest getDigest()
    {
        return digest;
    }

    /**
     * fill len bytes of the output buffer with bytes generated from the
     * derivation function.
     * 
     * @throws IllegalArgumentException
     *             if the size of the request will cause an overflow.
     * @throws DataLengthException
     *             if the out buffer is too small.
     */
    public int generateBytes(byte[] out, int outOff, int len) throws DataLengthException,
            IllegalArgumentException
    {
        if ((out.length - len) < outOff)
        {
            throw new OutputLengthException("output buffer too small");
        }

        digest.reset();

        int outputLength = len;
        int digestSize = digest.getDigestSize();

        // NOTE: This limit isn't reachable for current array lengths
        if (outputLength > ((1L << 32) - 1) * digestSize)
        {
            throw new IllegalArgumentException("Output length too large");
        }

        int counter32 = counterStart;
        byte[] C = new byte[4];

        while (len > 0)
        {
            Pack.intToBigEndian(counter32, C);

            digest.update(shared, 0, shared.length);
            digest.update(C, 0, 4);

            if (iv != null)
            {
                digest.update(iv, 0, iv.length);
            }

            if (len < digestSize)
            {
                byte[] tmp = new byte[digestSize];
                digest.doFinal(tmp, 0);
                System.arraycopy(tmp, 0, out, outOff, len);
                break;
            }

            digest.doFinal(out, outOff);
            outOff += digestSize;
            len -= digestSize;

            ++counter32;
        }

        return outputLength;
    }
}
