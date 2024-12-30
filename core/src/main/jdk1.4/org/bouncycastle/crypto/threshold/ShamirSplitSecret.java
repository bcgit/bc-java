package org.bouncycastle.crypto.threshold;

import java.io.IOException;

public class ShamirSplitSecret
    implements SplitSecret
{
    private final ShamirSplitSecretShare[] secretShares;
    private final Polynomial poly;

    public ShamirSplitSecret(ShamirSecretSplitter.Algorithm algorithm, ShamirSecretSplitter.Mode mode, ShamirSplitSecretShare[] secretShares)
    {
        this.secretShares = secretShares;
        this.poly = Polynomial.newInstance(algorithm, mode);
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
        byte[] r = new byte[n];
        byte tmp;
        byte[] products = new byte[n - 1];
        byte[][] splits = new byte[n][secretShares[0].getEncoded().length];
        for (int i = 0; i < n; i++)
        {
            splits[i] = secretShares[i].getEncoded();
            tmp = 0;
            for (int j = 0; j < n; j++)
            {
                if (j != i)
                {
                    products[tmp++] = poly.gfDiv(secretShares[j].r, secretShares[i].r ^ secretShares[j].r);
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
