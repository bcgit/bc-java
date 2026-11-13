package org.bouncycastle.crypto.threshold;

import java.io.IOException;

import org.bouncycastle.util.Arrays;

public class ShamirSplitSecret
    implements SplitSecret
{
    private final ShamirSplitSecretShare[] secretShares;
    private final Polynomial poly;

    /**
     * Recombine a set of shares using constant-time GF(256) arithmetic.
     *
     * @param algorithm the reduction polynomial the shares were produced over.
     * @param secretShares the shares to recombine.
     */
    public static ShamirSplitSecret getInstance(ShamirSecretSplitter.Algorithm algorithm, ShamirSplitSecretShare[] secretShares)
    {
        return new ShamirSplitSecret(new Polynomial(algorithm), secretShares);
    }

    /**
     * @deprecated the mode is ignored - see {@link ShamirSecretSplitter.Mode}. Use
     * {@link #getInstance(ShamirSecretSplitter.Algorithm, ShamirSplitSecretShare[])}.
     */
    @Deprecated
    public ShamirSplitSecret(ShamirSecretSplitter.Algorithm algorithm, ShamirSecretSplitter.Mode mode, ShamirSplitSecretShare[] secretShares)
    {
        this(new Polynomial(algorithm), secretShares);
    }

    ShamirSplitSecret(Polynomial poly, ShamirSplitSecretShare[] secretShares)
    {
        this.secretShares = secretShares;
        this.poly = poly;
    }

    public SecretShare[] getSecretShares()
    {
        return secretShares;
    }

    public ShamirSplitSecret multiple(int mul)
        throws IOException
    {
        // gfMul reduces the multiplier modulo 256, so any mul with (mul & 0xFF) == 0 is the field's
        // zero element, which would rewrite every share in place to zero and irreversibly destroy the
        // secret. The multiplier is a caller parameter rather than secret material, so rejecting it up
        // front leaks nothing.
        if ((mul & 0xFF) == 0)
        {
            throw new IllegalArgumentException("Invalid input: the multiplier cannot be zero.");
        }

        byte[] ss;
        for (int i = 0; i < secretShares.length; ++i)
        {
            ss = secretShares[i].getEncoded();
            for (int j = 0; j < ss.length; ++j)
            {
                ss[j] = poly.gfMul(ss[j] & 0xFF, mul);
            }
            secretShares[i] = new ShamirSplitSecretShare(ss, i + 1);
            Arrays.clear(ss);
        }
        return this;
    }

    public ShamirSplitSecret divide(int div)
        throws IOException
    {
        // gfPow/gfMul reduce the operand modulo 256, so any divisor with (div & 0xFF) == 0 - zero, or
        // a multiple of 256 - is the field's zero element. Division by zero is undefined, and every
        // share is rewritten in place, so accepting it would silently overwrite the whole set with
        // zeroes. The divisor is a caller parameter rather than secret material, so rejecting it up
        // front leaks nothing.
        if ((div & 0xFF) == 0)
        {
            throw new IllegalArgumentException("Invalid input: the divisor cannot be zero.");
        }

        // one inversion for the whole set, rather than one for every byte of every share
        int inverse = poly.gfPow(div, (byte)254) & 0xFF;

        byte[] ss;
        for (int i = 0; i < secretShares.length; ++i)
        {
            ss = secretShares[i].getEncoded();
            for (int j = 0; j < ss.length; ++j)
            {
                ss[j] = poly.gfMul(ss[j] & 0xFF, inverse);
            }
            secretShares[i] = new ShamirSplitSecretShare(ss, i + 1);
            Arrays.clear(ss);
        }
        return this;
    }

    @Override
    public byte[] getSecret()
        throws IOException
    {
        int n = secretShares.length;
        if (n == 0)
        {
            throw new IllegalArgumentException("Invalid input: at least one secret share is required.");
        }
        byte[] r = new byte[n];
        byte[][] splits = new byte[n][];
        try
        {
            for (int i = 0; i < n; i++)
            {
                splits[i] = secretShares[i].getEncoded();

                // the Lagrange coefficient is the product over j != i of x_j / (x_i - x_j): the numerators and
                // denominators are multiplied up separately and inverted once, as x^254 distributes over a
                // product, zero factors included.
                int numerator = 1;
                int denominator = 1;
                for (int j = 0; j < n; j++)
                {
                    if (j != i)
                    {
                        numerator = poly.gfMul(numerator, secretShares[j].r & 0xff) & 0xff;
                        denominator = poly.gfMul(denominator, (secretShares[i].r ^ secretShares[j].r) & 0xff) & 0xff;
                    }
                }
                r[i] = poly.gfMul(numerator, poly.gfPow(denominator, (byte)254) & 0xff);
            }

            return poly.gfVecMul(r, splits);
        }
        finally
        {
            // the copies of the shares taken above
            for (int i = 0; i < n; i++)
            {
                Arrays.clear(splits[i]);
            }
        }
    }
}
