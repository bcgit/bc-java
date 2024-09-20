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
        return gfMatMul(p, sr);
    }

    public int[][] recombine(int[] rr, int[][] splits)
    {
        return gfMatMul(getR(rr), splits);
    }

    protected abstract int gfMul(int x, int y);

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

    protected abstract int gfDiv(int x, int y);

    protected int gfProd(int[] ps)
    {
        int prod = 1;
        for (int p : ps)
        {
            prod = gfMul(prod, p);
        }
        return prod;
    }

    protected int gfDotProd(int[] xs, int[][] yss, int col)
    {
        int sum = 0;
        for (int i = 0; i < xs.length; i++)
        {
            sum = sum ^ gfMul(xs[i], yss[i][col]);
        }
        return sum;
    }

    protected int[][] gfMatMul(int[][] xss, int[][] yss)
    {
        int[][] result = new int[xss.length][yss[0].length];
        for (int i = 0; i < xss.length; i++)
        {
            for (int j = 0; j < yss[0].length; j++)
            {
                result[i][j] = gfDotProd(xss[i], yss, j);
            }
        }
        return result;
    }

    private int[][] getR(int[] input)
    {
        int n = input.length;
        int[][] result = new int[1][n];

        for (int i = 0; i < n; i++)
        {
            int[] products = new int[n - 1];
            int index = 0;

            for (int j = 0; j < n; j++)
            {
                if (j != i)
                {
                    products[index++] = gfDiv(input[j], input[i] ^ input[j]);
                }
            }

            result[0][i] = gfProd(products);
        }

        return result;
    }
}
