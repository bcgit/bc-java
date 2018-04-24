package org.bouncycastle.cert.dane;

import java.io.OutputStream;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;

/**
 * A calculator which produces a truncated digest from a regular one, with the truncation
 * achieved by dropping off the right most octets.
 */
public class TruncatingDigestCalculator
    implements DigestCalculator
{
    private final DigestCalculator baseCalculator;
    private final int length;

    /**
     * Default constructor - truncate to 28.
     *
     * @param baseCalculator actual calculator for working out the digest.
     */
    public TruncatingDigestCalculator(DigestCalculator baseCalculator)
    {
       this(baseCalculator, 28);
    }

    /**
     * Constructor specifying a length.
     *
     * @param baseCalculator actual calculator for working out the digest.
     * @param length length in bytes of the final result.
     */
    public TruncatingDigestCalculator(DigestCalculator baseCalculator, int length)
    {
        this.baseCalculator = baseCalculator;
        this.length = length;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return baseCalculator.getAlgorithmIdentifier();
    }

    public OutputStream getOutputStream()
    {
        return baseCalculator.getOutputStream();
    }

    public byte[] getDigest()
    {
        byte[] rv = new byte[length];

        byte[] dig = baseCalculator.getDigest();

        System.arraycopy(dig, 0, rv, 0, rv.length);

        return rv;
    }
}
