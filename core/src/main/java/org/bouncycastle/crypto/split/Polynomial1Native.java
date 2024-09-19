package org.bouncycastle.crypto.split;

public class Polynomial1Native
{
    // Irreducible polynomial: x^8 + x^4 + x^3 + x + 1
    private static final int IRREDUCIBLE = 0x11B;

    // Galois Field (2^8) operations
    public static int gfAdd(int x, int y)
    {
        return (x ^ y);
    }

    public static int gfSub(int x, int y)
    {
        return (x ^ y); // Addition and subtraction are the same in GF(2^8)
    }

    private static final int IRREDUCIBLE_POLY = 0x11b;
    public static int gfMul(int x, int y)
    {
        int result = pmult(x, y);
        return mod(result, IRREDUCIBLE);
    }

    private static int pmult(int x, int y) {
        int result = 0;
        while (y > 0) {
            if ((y & 1) != 0) {  // If the lowest bit of y is 1
                result ^= x;     // XOR x into the result
            }
            x <<= 1;             // Shift x left (multiply by 2 in GF)
            if ((x & 0x100) != 0) {  // If x is larger than 8 bits, reduce
                x ^= IRREDUCIBLE_POLY;  // XOR with the irreducible polynomial
            }
            y >>= 1;             // Shift y right
        }
        return result;
    }

    private static int mod(int value, int irreducible)
    {
        while (value >= (1 << 8))
        {
            if ((value & (1 << 8)) != 0)
            {
                value ^= irreducible;
            }
            value <<= 1;
        }
        return value & 0xFF;
    }

    public static int gfPow(int n, int k)
    {
        int result = 1;
        int[] base = new int[]{n};
        while (k > 0)
        {
            if ((k & 1) != 0)
            {
                result = gfMul(result, base[0]);
            }
            base[0] = gfMul(base[0], base[0]);
            k >>= 1;
        }
        return result;
    }

    public static int gfInv(int x)
    {
        return gfPow(x, 254); // Inverse is x^(2^8-2)
    }

    public static int gfDiv(int x, int y)
    {
        return gfMul(x, gfInv(y));
    }

    public static int[] gfSum(int[][] ps)
    {
        int[] result = new int[ps[0].length];
        for (int[] p : ps)
        {
            for (int i = 0; i < p.length; i++)
            {
                result[i] = gfAdd(result[i], p[i]);
            }
        }
        return result;
    }

    public static int gfProd(int[] ps)
    {
        int result = 1;
        for (int p : ps)
        {
            result = gfMul(result, p);
        }
        return result;
    }

    public static int gfDotProd(int[] xs, int[] ys)
    {
        int result = 0;
        for (int i = 0; i < xs.length; i++)
        {
            result = gfAdd(result, gfMul(xs[i], ys[i]));
        }
        return result;
    }
    public static int[] gfVecMul(int[] v, int[][] ms)
    {
        int[] result = new int[ms[0].length];
        for (int i = 0; i < ms[0].length; i++)
        {
            result[i] = gfDotProd(v, getColumn(ms, i));
        }
        return result;
    }
    public static int[][] gfMatMul(int[][] xss, int[][] yss)
    {
        int[][] result = new int[xss.length][yss[0].length];
        for (int i = 0; i < xss.length; i++)
        {
            result[i] = gfVecMul(xss[i], yss);
        }
        return result;
    }

    private static int[][] transpose(int[][] matrix)
    {
        int rows = matrix.length;
        int cols = matrix[0].length;
        int[][] transposed = new int[cols][rows];
        for (int i = 0; i < rows; i++)
        {
            for (int j = 0; j < cols; j++)
            {
                transposed[j][i] = matrix[i][j];
            }
        }
        return transposed;
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
