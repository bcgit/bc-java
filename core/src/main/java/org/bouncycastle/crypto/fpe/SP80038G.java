package org.bouncycastle.crypto.fpe;

import java.math.BigInteger;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.util.RadixConverter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

/*
 * SP800-38G Format-Preserving Encryption
 *
 * TODOs
 * - Initialize the cipher internally or externally?
 *     1. Algs 7-10 don't appear to require forward vs. inverse transform, although sample data is forward.
 *     2. Algs 9-10 specify reversal of the cipher key!
 * - Separate construction/initialization stage for "prerequisites"
 */
class SP80038G
{

    static final String FPE_DISABLED = "org.bouncycastle.fpe.disable";
    static final String FF1_DISABLED = "org.bouncycastle.fpe.disable_ff1";

    protected static final int BLOCK_SIZE = 16;
    protected static final double LOG2 = Math.log(2.0);
    protected static final double TWO_TO_96 = Math.pow(2, 96);

    static byte[] decryptFF1(BlockCipher cipher, RadixConverter radixConverter, byte[] tweak, byte[] buf, int off, int len)
    {
        checkArgs(cipher, true, radixConverter.getRadix(), buf, off, len);

        // Algorithm 8
        int n = len;
        int u = n / 2, v = n - u;

        short[] A = toShort(buf, off, u);
        short[] B = toShort(buf, off + u, v);

        short[] rv = decFF1(cipher, radixConverter, tweak, n, u, v, A, B);

        return toByte(rv);
    }

    static short[] decryptFF1w(BlockCipher cipher, RadixConverter radixConverter, byte[] tweak, short[] buf, int off, int len)
    {
        checkArgs(cipher, true, radixConverter.getRadix(), buf, off, len);

        // Algorithm 8
        int n = len;
        int u = n / 2, v = n - u;

        short[] A = new short[u];
        short[] B = new short[v];

        System.arraycopy(buf, off, A, 0, u);
        System.arraycopy(buf, off + u, B, 0, v);

        return decFF1(cipher, radixConverter, tweak, n, u, v, A, B);
    }

    static short[] decFF1(BlockCipher cipher, RadixConverter radixConverter, byte[] T, int n, int u, int v, short[] A, short[] B)
    {
        int radix = radixConverter.getRadix();
        int t = T.length;
        int b = calculateB_FF1(radix, v);
        int d = (b + 7) & ~3;

        byte[] P = calculateP_FF1(radix, (byte)u, n, t);

        BigInteger bigRadix = BigInteger.valueOf(radix);
        BigInteger[] modUV = calculateModUV(bigRadix, u, v);

        int m = u;

        for (int i = 9; i >= 0; --i)
        {
            // i. - iv.
            BigInteger y = calculateY_FF1(cipher, T, b, d, i, P, A, radixConverter);

            // v.
            m = n - m;
            BigInteger modulus = modUV[i & 1];

            // vi.
            BigInteger c = radixConverter.fromEncoding(B).subtract(y).mod(modulus);

            // vii. - ix.
            short[] C = B;
            B = A;
            A = C;
            radixConverter.toEncoding(c, m, C);
        }

        return Arrays.concatenate(A, B);
    }

    static byte[] decryptFF3(BlockCipher cipher, RadixConverter radixConverter, byte[] tweak64, byte[] buf, int off, int len)
    {
        checkArgs(cipher, false, radixConverter.getRadix(), buf, off, len);

        if (tweak64.length != 8)
        {
            throw new IllegalArgumentException();
        }

        return implDecryptFF3(cipher, radixConverter, tweak64, buf, off, len);
    }

    static byte[] decryptFF3_1(BlockCipher cipher, RadixConverter radixConverter, byte[] tweak56, byte[] buf, int off, int len)
    {
        checkArgs(cipher, false, radixConverter.getRadix(), buf, off, len);

        if (tweak56.length != 7)
        {
            throw new IllegalArgumentException("tweak should be 56 bits");
        }

        byte[] tweak64 = calculateTweak64_FF3_1(tweak56);

        return implDecryptFF3(cipher, radixConverter, tweak64, buf, off, len);
    }

    static short[] decryptFF3_1w(BlockCipher cipher, RadixConverter radixConverter, byte[] tweak56, short[] buf, int off, int len)
    {
        checkArgs(cipher, false, radixConverter.getRadix(), buf, off, len);

        if (tweak56.length != 7)
        {
            throw new IllegalArgumentException("tweak should be 56 bits");
        }

        byte[] tweak64 = calculateTweak64_FF3_1(tweak56);

        return implDecryptFF3w(cipher, radixConverter, tweak64, buf, off, len);
    }

    static byte[] encryptFF1(BlockCipher cipher, RadixConverter radixConverter, byte[] tweak, byte[] buf, int off, int len)
    {
        checkArgs(cipher, true, radixConverter.getRadix(), buf, off, len);

        // Algorithm 7
        int n = len;
        int u = n / 2, v = n - u;

        short[] A = toShort(buf, off, u);
        short[] B = toShort(buf, off + u, v);

        return toByte(encFF1(cipher, radixConverter, tweak, n, u, v, A, B));
    }

    static short[] encryptFF1w(BlockCipher cipher, RadixConverter radixConverter, byte[] tweak, short[] buf, int off, int len)
    {
        checkArgs(cipher, true, radixConverter.getRadix(), buf, off, len);

        // Algorithm 7
        int n = len;
        int u = n / 2, v = n - u;

        short[] A = new short[u];
        short[] B = new short[v];

        System.arraycopy(buf, off, A, 0, u);
        System.arraycopy(buf, off + u, B, 0, v);

        return encFF1(cipher, radixConverter, tweak, n, u, v, A, B);
    }

    private static short[] encFF1(BlockCipher cipher, RadixConverter radixConverter, byte[] T, int n, int u, int v, short[] A, short[] B)
    {
        int radix = radixConverter.getRadix();
        int t = T.length;

        int b = calculateB_FF1(radix, v);
        int d = (b + 7) & ~3;

        byte[] P = calculateP_FF1(radix, (byte)u, n, t);

        BigInteger bigRadix = BigInteger.valueOf(radix);
        BigInteger[] modUV = calculateModUV(bigRadix, u, v);

        int m = v;

        for (int i = 0; i < 10; ++i)
        {
            // i. - iv.
            BigInteger y = calculateY_FF1(cipher, T, b, d, i, P, B, radixConverter);

            // v.
            m = n - m;
            BigInteger modulus = modUV[i & 1];

            // vi.
            BigInteger num = radixConverter.fromEncoding(A);
            BigInteger c = num.add(y).mod(modulus);

            // vii. - ix.
            short[] C = A;
            A = B;
            B = C;
            radixConverter.toEncoding(c, m, C);
        }

        return Arrays.concatenate(A, B);
    }

    static byte[] encryptFF3(BlockCipher cipher, RadixConverter radixConverter, byte[] tweak64, byte[] buf, int off, int len)
    {
        checkArgs(cipher, false, radixConverter.getRadix(), buf, off, len);

        if (tweak64.length != 8)
        {
            throw new IllegalArgumentException();
        }

        return implEncryptFF3(cipher, radixConverter, tweak64, buf, off, len);
    }

    static short[] encryptFF3w(BlockCipher cipher, RadixConverter radixConverter, byte[] tweak64, short[] buf, int off, int len)
    {
        checkArgs(cipher, false, radixConverter.getRadix(), buf, off, len);

        if (tweak64.length != 8)
        {
            throw new IllegalArgumentException();
        }

        return implEncryptFF3w(cipher, radixConverter, tweak64, buf, off, len);
    }

    static short[] encryptFF3_1w(BlockCipher cipher, RadixConverter radixConverter, byte[] tweak56, short[] buf, int off, int len)
    {
        checkArgs(cipher, false, radixConverter.getRadix(), buf, off, len);

        if (tweak56.length != 7)
        {
            throw new IllegalArgumentException("tweak should be 56 bits");
        }
        byte[] tweak64 = calculateTweak64_FF3_1(tweak56);

        return encryptFF3w(cipher, radixConverter, tweak64, buf, off, len);
    }

    static byte[] encryptFF3_1(BlockCipher cipher, RadixConverter radixConverter, byte[] tweak56, byte[] buf, int off, int len)
    {
        checkArgs(cipher, false, radixConverter.getRadix(), buf, off, len);

        if (tweak56.length != 7)
        {
            throw new IllegalArgumentException("tweak should be 56 bits");
        }

        byte[] tweak64 = calculateTweak64_FF3_1(tweak56);

        return encryptFF3(cipher, radixConverter, tweak64, buf, off, len);
    }

    protected static int calculateB_FF1(int radix, int v)
    {
//        return (BigInteger.valueOf(radix).pow(v).subtract(BigInteger.ONE).bitLength() + 7) / 8;

        int powersOfTwo = Integers.numberOfTrailingZeros(radix); 
        int bits = powersOfTwo * v;

        int oddPart = radix >>> powersOfTwo;
        if (oddPart != 1)
        {
            // Old version with rounding issues, especially for power of 2 radix, but maybe others.
//            bits += (int)Math.ceil(Math.log((double)oddPart) * (double)v / LOG2);

            // Exact calculation, with possible performance issues if v is too large.
            bits += BigInteger.valueOf(oddPart).pow(v).bitLength();
        }

        return (bits + 7) / 8;
    }

    protected static BigInteger[] calculateModUV(BigInteger bigRadix, int u, int v)
    {
        BigInteger[] modUV = new BigInteger[2];
        modUV[0] = bigRadix.pow(u);
        modUV[1] = modUV[0];
        if (v != u)
        {
            modUV[1] = modUV[1].multiply(bigRadix);
        }
        return modUV;
    }

    protected static byte[] calculateP_FF1(int radix, byte uLow, int n, int t)
    {
        byte[] P = new byte[BLOCK_SIZE];
        P[0] = 1;
        P[1] = 2;
        P[2] = 1;

        // Radix
        P[3] = 0;
        P[4] = (byte)(radix >> 8);
        P[5] = (byte)radix;

        P[6] = 10;
        P[7] = uLow;
        Pack.intToBigEndian(n, P, 8);
        Pack.intToBigEndian(t, P, 12);
        return P;
    }

    protected static byte[] calculateTweak64_FF3_1(byte[] tweak56)
    {
        byte[] tweak64 = new byte[8];
        tweak64[0] = tweak56[0];
        tweak64[1] = tweak56[1];
        tweak64[2] = tweak56[2];
        tweak64[3] = (byte)(tweak56[3] & 0xF0);
        tweak64[4] = tweak56[4];
        tweak64[5] = tweak56[5];
        tweak64[6] = tweak56[6];
        tweak64[7] = (byte)(tweak56[3] << 4);

        return tweak64;
    }

    protected static BigInteger calculateY_FF1(BlockCipher cipher, byte[] T, int b, int d, int round, byte[] P, short[] AB,
                                               RadixConverter radixConverter)
    {
        int t = T.length;

        // i.
        BigInteger numAB = radixConverter.fromEncoding(AB);
        byte[] bytesAB = BigIntegers.asUnsignedByteArray(numAB);

        int zeroes = -(t + b + 1) & 15;
        byte[] Q = new byte[t + zeroes + 1 + b];
        System.arraycopy(T, 0, Q, 0, t);
        Q[t + zeroes] = (byte)round;
        System.arraycopy(bytesAB, 0, Q, Q.length - bytesAB.length, bytesAB.length);

        // ii.
        byte[] R = prf(cipher, Arrays.concatenate(P, Q));

        // iii.
        byte[] sBlocks = R;
        if (d > BLOCK_SIZE)
        {
            int sBlocksLen = (d + BLOCK_SIZE - 1) / BLOCK_SIZE;
            sBlocks = new byte[sBlocksLen * BLOCK_SIZE];
            System.arraycopy(R, 0, sBlocks, 0, BLOCK_SIZE);

            byte[] uint32 = new byte[4];
            for (int j = 1; j < sBlocksLen; ++j)
            {
                int sOff = j * BLOCK_SIZE;
                System.arraycopy(R, 0, sBlocks, sOff, BLOCK_SIZE);
                Pack.intToBigEndian(j, uint32, 0);
                xor(uint32, 0, sBlocks, sOff + BLOCK_SIZE - 4, 4);
                cipher.processBlock(sBlocks, sOff, sBlocks, sOff);
            }
        }

        // iv.
        return num(sBlocks, 0, d);
    }

    protected static BigInteger calculateY_FF3(BlockCipher cipher, byte[] T, int wOff, int round, short[] AB, RadixConverter radixConverter)
    {
        // ii.
        byte[] P = new byte[BLOCK_SIZE];
        Pack.intToBigEndian(round, P, 0);
        xor(T, wOff, P, 0, 4);
        BigInteger numAB = radixConverter.fromEncoding(AB);

        byte[] bytesAB = BigIntegers.asUnsignedByteArray(numAB);

        if ((P.length - bytesAB.length) < 4)  // to be sure...
        {
            throw new IllegalStateException("input out of range");
        }
        System.arraycopy(bytesAB, 0, P, P.length - bytesAB.length, bytesAB.length);

        // iii.
        rev(P);
        cipher.processBlock(P, 0, P, 0);
        rev(P);
        byte[] S = P;

        // iv.
        return num(S, 0, S.length);
    }

    protected static void checkArgs(BlockCipher cipher, boolean isFF1, int radix, short[] buf, int off, int len)
    {
        checkCipher(cipher);
        if (radix < 2 || radix > (1 << 16))
        {
            throw new IllegalArgumentException();
        }
        checkData(isFF1, radix, buf, off, len);
    }

    protected static void checkArgs(BlockCipher cipher, boolean isFF1, int radix, byte[] buf, int off, int len)
    {
        checkCipher(cipher);
        if (radix < 2 || radix > (1 << 8))
        {
            throw new IllegalArgumentException();
        }
        checkData(isFF1, radix, buf, off, len);
    }

    protected static void checkCipher(BlockCipher cipher)
    {
        if (BLOCK_SIZE != cipher.getBlockSize())
        {
            throw new IllegalArgumentException();
        }
    }

    protected static void checkData(boolean isFF1, int radix, short[] buf, int off, int len)
    {
        checkLength(isFF1, radix, len);
        for (int i = 0; i < len; ++i)
        {
            int b = buf[off + i] & 0xFFFF;
            if (b >= radix)
            {
                throw new IllegalArgumentException("input data outside of radix");
            }
        }
    }

    protected static void checkData(boolean isFF1, int radix, byte[] buf, int off, int len)
    {
        checkLength(isFF1, radix, len);
        for (int i = 0; i < len; ++i)
        {
            int b = buf[off + i] & 0xFF;
            if (b >= radix)
            {
                throw new IllegalArgumentException("input data outside of radix");
            }
        }
    }

    private static void checkLength(boolean isFF1, int radix, int len)
    {
        if (len < 2 || Math.pow(radix, len) < 1000000)
        {
            throw new IllegalArgumentException("input too short");
        }
        if (!isFF1)
        {
            int maxLen = 2 * (int)(Math.floor(Math.log(TWO_TO_96) / Math.log(radix)));
            if (len > maxLen)
            {
                throw new IllegalArgumentException("maximum input length is " + maxLen);
            }
        }
    }

    protected static byte[] implDecryptFF3(BlockCipher cipher, RadixConverter radixConverter, byte[] tweak64, byte[] buf, int off, int len)
    {
        // Algorithm 10
        byte[] T = tweak64;
        int n = len;
        int v = n / 2, u = n - v;

        short[] A = toShort(buf, off, u);
        short[] B = toShort(buf, off + u, v);

        short[] rv = decFF3_1(cipher, radixConverter, T, n, v, u, A, B);

        return toByte(rv);
    }

    protected static short[] implDecryptFF3w(BlockCipher cipher, RadixConverter radixConverter, byte[] tweak64, short[] buf, int off, int len)
    {
        // Algorithm 10
        byte[] T = tweak64;
        int n = len;
        int v = n / 2, u = n - v;

        short[] A = new short[u];
        short[] B = new short[v];

        System.arraycopy(buf, off, A, 0, u);
        System.arraycopy(buf, off + u, B, 0, v);

        return decFF3_1(cipher, radixConverter, T, n, v, u, A, B);
    }

    private static short[] decFF3_1(BlockCipher cipher, RadixConverter radixConverter, byte[] T, int n, int v, int u, short[] A, short[] B)
    {
        BigInteger bigRadix = BigInteger.valueOf(radixConverter.getRadix());
        BigInteger[] modVU = calculateModUV(bigRadix, v, u);

        int m = u;

        // Note we keep A, B in reverse order throughout
        rev(A);
        rev(B);

        for (int i = 7; i >= 0; --i)
        {
            // i.
            m = n - m;
            BigInteger modulus = modVU[1 - (i & 1)];
            int wOff = 4 - ((i & 1) * 4);

            // ii. - iv.
            BigInteger y = calculateY_FF3(cipher, T, wOff, i, A, radixConverter);

            // v.
            BigInteger c = radixConverter.fromEncoding(B).subtract(y).mod(modulus);

            // vi. - viii.
            short[] C = B;
            B = A;
            A = C;
            radixConverter.toEncoding(c, m, C);
        }

        rev(A);
        rev(B);

        return Arrays.concatenate(A, B);
    }

    protected static byte[] implEncryptFF3(BlockCipher cipher, RadixConverter radixConverter, byte[] tweak64, byte[] buf, int off, int len)
    {
        // Algorithm 9
        byte[] T = tweak64;
        int n = len;
        int v = n / 2, u = n - v;

        short[] A = toShort(buf, off, u);
        short[] B = toShort(buf, off + u, v);

        short[] rv = encFF3_1(cipher, radixConverter, T, n, v, u, A, B);

        return toByte(rv);
    }

    protected static short[] implEncryptFF3w(BlockCipher cipher, RadixConverter radixConverter, byte[] tweak64, short[] buf, int off, int len)
    {
        // Algorithm 9
        byte[] T = tweak64;
        int n = len;
        int v = n / 2, u = n - v;

        short[] A = new short[u];
        short[] B = new short[v];

        System.arraycopy(buf, off, A, 0, u);
        System.arraycopy(buf, off + u, B, 0, v);

        return encFF3_1(cipher, radixConverter, T, n, v, u, A, B);
    }

    private static short[] encFF3_1(BlockCipher cipher, RadixConverter radixConverter, byte[] t, int n, int v, int u, short[] a, short[] b)
    {
        BigInteger bigRadix = BigInteger.valueOf(radixConverter.getRadix());
        BigInteger[] modVU = calculateModUV(bigRadix, v, u);

        int m = v;

        // Note we keep A, B in reverse order throughout
        rev(a);
        rev(b);

        for (int i = 0; i < 8; ++i)
        {
            // i.
            m = n - m;
            BigInteger modulus = modVU[1 - (i & 1)];
            int wOff = 4 - ((i & 1) * 4);

            // ii. - iv.
            BigInteger y = calculateY_FF3(cipher, t, wOff, i, b, radixConverter);

            // v.
            BigInteger c = radixConverter.fromEncoding(a).add(y).mod(modulus);

            // vi. - viii.
            short[] C = a;
            a = b;
            b = C;
            radixConverter.toEncoding(c, m, C);
        }

        rev(a);
        rev(b);

        return Arrays.concatenate(a, b);
    }

    protected static BigInteger num(byte[] buf, int off, int len)
    {
        return new BigInteger(1, Arrays.copyOfRange(buf, off, off + len));
    }

    protected static byte[] prf(BlockCipher c, byte[] x)
    {
        if ((x.length % BLOCK_SIZE) != 0)
        {
            throw new IllegalArgumentException();
        }

        int m = x.length / BLOCK_SIZE;
        byte[] y = new byte[BLOCK_SIZE];

        for (int i = 0; i < m; ++i)
        {
            xor(x, i * BLOCK_SIZE, y, 0, BLOCK_SIZE);
            c.processBlock(y, 0, y, 0);
        }

        return y;
    }

//    protected static void rev(byte[] x, int xOff, byte[] y, int yOff, int len)
//    {
//        for (int i = 1; i <= len; ++i)
//        {
//            y[yOff + len - i] = x[xOff + i - 1];
//        }
//    }

    protected static void rev(byte[] x)
    {
        int half = x.length / 2, end = x.length - 1;
        for (int i = 0; i < half; ++i)
        {
            byte tmp = x[i];
            x[i] = x[end - i];
            x[end - i] = tmp;
        }
    }

    protected static void rev(short[] x)
    {
        int half = x.length / 2, end = x.length - 1;
        for (int i = 0; i < half; ++i)
        {
            short tmp = x[i];
            x[i] = x[end - i];
            x[end - i] = tmp;
        }
    }

    protected static void xor(byte[] x, int xOff, byte[] y, int yOff, int len)
    {
        for (int i = 0; i < len; ++i)
        {
            y[yOff + i] ^= x[xOff + i];
        }
    }

    private static byte[] toByte(short[] buf)
    {
        byte[] s = new byte[buf.length];

        for (int i = 0; i != s.length; i++)
        {
            s[i] = (byte)buf[i];
        }

        return s;
    }

    private static short[] toShort(byte[] buf, int off, int len)
    {
        short[] s = new short[len];

        for (int i = 0; i != s.length; i++)
        {
            s[i] = (short)(buf[off + i] & 0xFF);
        }

        return s;
    }
}
