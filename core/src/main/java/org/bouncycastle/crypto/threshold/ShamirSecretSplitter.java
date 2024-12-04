package org.bouncycastle.crypto.threshold;

import java.security.SecureRandom;

public abstract class ShamirSecretSplitter
    implements SecretSplitter
{
    public static final int AES = 0;
    public static final int RSA = 1;
    /**
     * Length of the secret
     */
    protected int l;
    /**
     * A threshold number of shares
     */
    protected int m;
    /**
     * Total number of shares
     * m <= n <= 255
     */
    protected int n;
    protected byte[][] p;
    protected SecureRandom random;

    protected ShamirSecretSplitter(int l, int m, int n, SecureRandom random)
    {
        if (l < 0 || l > 65534)
        {
            throw new IllegalArgumentException("Invalid input: l ranges from 0 to 65534 (2^16-2) bytes.");
        }
        if (m < 1 || m > 255)
        {
            throw new IllegalArgumentException("Invalid input: m must be less than 256 and positive.");
        }
        if (n < m || n > 255)
        {
            throw new IllegalArgumentException("Invalid input: n must be less than 256 and greater than or equal to n.");
        }
        this.l = l;
        this.m = m;
        this.n = n;
        this.random = random;
    }

    protected void init()
    {
        p = new byte[n][m];
        for (int i = 0; i < n; i++)
        {
            for (int j = 0; j < m; j++)
            {
                p[i][j] = gfPow((byte)(i + 1), (byte)j);
            }
        }
    }

    public ShamirSplitSecret split()
    {
        byte[][] sr = new byte[m][l];
        ShamirSplitSecretShare[] secretShares = new ShamirSplitSecretShare[l];
        int i;
        for (i = 0; i < m; ++i)
        {
            random.nextBytes(sr[i]);
        }
        for (i = 0; i < p.length; i++)
        {
            secretShares[i] = new ShamirSplitSecretShare(gfVecMul(p[i], sr), i + 1);
        }
        return new ShamirSplitSecret(secretShares);
    }

    public byte[] recombineShares(int[] rr, byte[]... splits)
    {
        int n = rr.length;
        byte[] r = new byte[n];
        byte tmp;
        byte[] products = new byte[n - 1];
        for (int i = 0; i < n; i++)
        {
            tmp = 0;
            for (int j = 0; j < n; j++)
            {
                if (j != i)
                {
                    products[tmp++] = gfDiv(rr[j], rr[i] ^ rr[j]);
                }
            }

            tmp = 1;
            for (byte p : products)
            {
                tmp = (byte)gfMul(tmp & 0xff, p & 0xff);
            }
            r[i] = tmp;
        }

        return gfVecMul(r, splits);
    }

    protected abstract int gfMul(int x, int y);

    protected abstract byte gfDiv(int x, int y);

    protected byte gfPow(int n, byte k)
    {
        int result = 1;
        for (int i = 0; i < 8; i++)
        {
            if ((k & (1 << i)) != 0)
            {
                result = (byte)gfMul(result & 0xff, n & 0xff);
            }
            n = gfMul(n & 0xff, n & 0xff);
        }
        return (byte)result;
    }

    private byte[] gfVecMul(byte[] xs, byte[][] yss)
    {
        byte[] result = new byte[yss[0].length];
        int sum;
        for (int j = 0; j < yss[0].length; j++)
        {
            sum = 0;
            for (int k = 0; k < xs.length; k++)
            {
                sum ^= gfMul(xs[k] & 0xff, yss[k][j] & 0xff);
            }
            result[j] = (byte)sum;
        }
        return result;
    }
}
