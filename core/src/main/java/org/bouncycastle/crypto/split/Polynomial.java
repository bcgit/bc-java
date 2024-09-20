package org.bouncycastle.crypto.split;

public abstract class Polynomial
{
    public static final int AES = 0;
    public static final int RSA = 1;

    public static int gfAdd(int x, int y)
    {
        return x ^ y;
    }

    public abstract int gfMul(int x, int y);

    public abstract int gfPow(int n, int k);

    public abstract int gfDiv(int x, int y);

    public int gfProd(int[] ps)
    {
        int prod = 1;
        for (int p : ps)
        {
            prod = gfMul(prod, p);
        }
        return prod;
    }

    public int gfDotProd(int[] xs, int[] ys)
    {
        int sum = 0;
        for (int i = 0; i < xs.length; i++)
        {
            sum = Polynomial.gfAdd(sum, gfMul(xs[i], ys[i]));
        }
        return sum;
    }

    public int[] gfVecMul(int[] v, int[][] ms)
    {
        int[] result = new int[ms[0].length];
        for (int i = 0; i < ms[0].length; i++)
        {
            result[i] = gfDotProd(v, getColumn(ms, i));
        }
        return result;
    }

    public int[][] gfMatMul(int[][] xss, int[][] yss)
    {
        int[][] result = new int[xss.length][yss[0].length];
        for (int i = 0; i < xss.length; i++)
        {
            result[i] = gfVecMul(xss[i], yss);
        }
        return result;
    }

    private static int[] getColumn(int[][] matrix, int col)
    {
        int[] column = new int[matrix.length];
        for (int i = 0; i < matrix.length; i++)
        {
            column[i] = matrix[i][col];
        }
        return column;
    }
}
