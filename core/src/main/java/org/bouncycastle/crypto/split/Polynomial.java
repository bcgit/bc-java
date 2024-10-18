package org.bouncycastle.crypto.split;

public abstract class Polynomial
{
    public static final byte AES = 0;
    public static final byte RSA = 1;
    /**
     * <summary>
     * Length of the secret
     * </summary>
     */
    protected int l;
    /**
     * <summary>
     * A threshold number of shares
     * </summary>
     */
    protected int m;
    /**
     * <summary>
     * Total number of shares
     * m <= n <= 255
     * </summary>
     */
    protected int n;
    protected byte[][] p;

    protected Polynomial(int l, int m, int n)
    {
        //TODO: check m <= n <= 255
        this.l = l;
        this.m = m;
        this.n = n;
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

    public byte[][] createShares(byte[][] sr)
    {
        byte[][] result = new byte[p.length][sr[0].length];
        for (int i = 0; i < p.length; i++)
        {
            result[i] = gfVecMul(p[i], sr);
        }
        return result;
    }

    public byte[] recombine(byte[] rr, byte[][] splits)
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
                    products[tmp++] = gfDiv(rr[j] & 0xff, (rr[i] ^ rr[j]) & 0xff);
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
                result = (byte) gfMul(result & 0xff, n & 0xff);
            }
            n = gfMul(n & 0xff, n & 0xff);
        }
        return (byte) result;
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
            result[j] = (byte) sum;
        }
        return result;
    }
}
