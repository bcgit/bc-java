package org.bouncycastle.crypto.split;

public abstract class Polynomial
{
    public static final int AES = 0;
    public static final int RSA = 1;
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
    protected int[][] p;

    protected Polynomial(int l, int m, int n)
    {
        this.l = l;
        this.m = m;
        this.n = n;
    }

    protected void init()
    {
        p = new int[n][m];
        for (int i = 0; i < n; i++)
        {
            for (int j = 0; j < m; j++)
            {
                p[i][j] = gfPow(i + 1, j);
            }
        }
    }

    public int[][] createShares(int[][] sr)
    {
        int[][] result = new int[p.length][sr[0].length];
        for (int i = 0; i < p.length; i++)
        {
            result[i] = gfVecMul(p[i], sr);
        }
        return result;
    }

    public int[] recombine(int[] rr, int[][] splits)
    {
        int n = rr.length;
        int[] r = new int[n];
        int tmp;
        int[] products = new int[n - 1];
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
            for (int p : products)
            {
                tmp = gfMul(tmp, p);
            }
            r[i] = tmp;
        }

        return gfVecMul(r, splits);
    }

    protected abstract int gfMul(int x, int y);

    protected abstract int gfDiv(int x, int y);

    protected int gfPow(int n, int k)
    {
        int result = 1;
        for (int i = 0; i < 8; i++)
        {
            if ((k & (1 << i)) != 0)
            {
                result = gfMul(result, n);
            }
            n = gfMul(n, n);
        }
        return result;
    }

    private int[] gfVecMul(int[] xs, int[][] yss)
    {
        int[] result = new int[yss[0].length];
        int sum;
        for (int j = 0; j < yss[0].length; j++)
        {
            sum = 0;
            for (int k = 0; k < xs.length; k++)
            {
                sum = sum ^ gfMul(xs[k], yss[k][j]);
            }
            result[j] = sum;
        }
        return result;
    }
}
