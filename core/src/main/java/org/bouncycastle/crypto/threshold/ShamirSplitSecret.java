package org.bouncycastle.crypto.threshold;

import java.io.IOException;

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

    public ShamirSplitSecretShare[] getSecretShares()
    {
        return secretShares;
    }

    public ShamirSplitSecret multiple(int mul)
        throws IOException
    {
        byte[] ss;
        for (int i = 0; i < secretShares.length; ++i)
        {
            ss = secretShares[i].getEncoded();
            for (int j = 0; j < ss.length; ++j)
            {
                ss[j] = poly.gfMul(ss[j] & 0xFF, mul);
            }
            secretShares[i] = new ShamirSplitSecretShare(ss, i + 1);
        }
        return this;
    }

    public ShamirSplitSecret divide(int div)
        throws IOException
    {
        // division by zero is undefined in the field, and every share is rewritten in place, so
        // accepting it would silently overwrite the whole set with zeroes. The divisor is a caller
        // parameter rather than secret material, so rejecting it up front leaks nothing.
        if (div == 0)
        {
            throw new IllegalArgumentException("Invalid input: the divisor cannot be zero.");
        }

        byte[] ss;
        for (int i = 0; i < secretShares.length; ++i)
        {
            ss = secretShares[i].getEncoded();
            for (int j = 0; j < ss.length; ++j)
            {
                ss[j] = poly.gfDiv(ss[j] & 0xFF, div);
            }
            secretShares[i] = new ShamirSplitSecretShare(ss, i + 1);
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
        byte tmp;
        byte[] products = new byte[n - 1];
        byte[][] splits = new byte[n][secretShares[0].getEncoded().length];
        for (int i = 0; i < n; i++)
        {
            splits[i] = secretShares[i].getEncoded();
            int prdCount = 0;
            for (int j = 0; j < n; j++)
            {
                if (j != i)
                {
                    products[prdCount++] = poly.gfDiv(secretShares[j].r, secretShares[i].r ^ secretShares[j].r);
                }
            }

            tmp = 1;
            for (int prdI = 0; prdI != products.length; prdI++)
            {
                tmp = poly.gfMul(tmp & 0xff, products[prdI] & 0xff);
            }
            r[i] = tmp;
        }

        return poly.gfVecMul(r, splits);
    }
}
