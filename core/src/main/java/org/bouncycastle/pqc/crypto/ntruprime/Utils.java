package org.bouncycastle.pqc.crypto.ntruprime;

import java.security.SecureRandom;

import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Pack;

class Utils
{
    /**
     * Fill L with uniform random 32-bit words, drawn in a single call and decoded little-endian. The reference draws
     * each word by its own 4-byte call (urandom32), so with a deterministic generator such as the KATs', which
     * discards the rest of its last block on every call, its words differ from this single call's; the KAT tests split
     * this request to match.
     */
    private static void getRandomUnsignedIntegers(SecureRandom random, int[] L)
    {
        byte[] bytes = new byte[L.length * 4];
        random.nextBytes(bytes);
        Pack.littleEndianToInt(bytes, 0, L);
    }

    protected static void getRandomSmallPolynomial(SecureRandom random, byte[] g)
    {
        int[] L = new int[g.length];
        getRandomUnsignedIntegers(random, L);
        for (int i = 0; i < g.length; i++)
            g[i] = (byte)((((L[i] & 0x3fffffff) * 3) >>> 30) - 1);
    }

    /**
     * floor(2^32 / 3), the factor getModFreeze() takes for reductions modulo 3.
     */
    static final long BARRETT_3 = 0x100000000L / 3;

    /**
     * Return floor(2^32 / n), the factor getModFreeze() takes for modulus n. The modulus is public, so dividing by
     * it here is safe; callers compute the factor once, outside their loops.
     */
    protected static long getBarrettFactor(int n)
    {
        return 0x100000000L / n;
    }

    /**
     * Return x mod n in [-(n - 1) / 2, (n - 1) / 2], for n = 3 or q and any x with x + (n - 1) / 2 in the int range,
     * without branches, divisions or allocation. The multiply-shift estimate of the quotient is the true quotient or
     * one off it either way, leaving a remainder in [-n, 2n) that two masked corrections bring into [0, n).
     *
     * @param barrett getBarrettFactor(n).
     */
    protected static int getModFreeze(int x, int n, long barrett)
    {
        int y = x + ((n - 1) / 2);
        int r = y - n * (int)((y * barrett) >> 32);
        r += n & (r >> 31);
        r -= n;
        r += n & (r >> 31);
        return r - ((n - 1) / 2);
    }

    /**
     * Return x mod 3 in {-1, 0, 1} for x in [-2, 2], without branches.
     */
    private static int getSmallModFreeze3(int x)
    {
        return x + 3 * (((1 - x) >> 31) - ((x + 1) >> 31));
    }

    protected static boolean isInvertiblePolynomialInR3(byte[] g, byte[] ginv, int p)
    {
        byte[] f = new byte[p + 1];
        byte[] h = new byte[p + 1];
        byte[] r = new byte[p + 1];
        byte[] v = new byte[p + 1];
        int loop, delta, sign, swap, t, i;

        r[0] = 1;
        f[0] = 1;
        f[p - 1] = -1;
        f[p] = -1;
        for (i = 0; i < p; i++)
            h[p - 1 - i] = g[i];

        h[p] = 0;
        delta = 1;

        for (loop = 0; loop < (2 * p) - 1; loop++)
        {
            System.arraycopy(v, 0, v, 1, p);
            v[0] = 0;

            sign = -h[0] * f[0];
            swap = checkLessThanZero(-delta) & checkNotEqualToZero(h[0]);
            delta ^= swap & (delta ^ -delta);
            delta += 1;

            for (i = 0; i < p + 1; i++)
            {
                t = swap & (f[i] ^ h[i]);
                f[i] ^= t;
                h[i] ^= t;
                t = swap & (v[i] ^ r[i]);
                v[i] ^= t;
                r[i] ^= t;
            }

            // g is small, so f, h, r, v and sign all stay in {-1, 0, 1} and the sums in [-2, 2]
            for (i = 0; i < p + 1; i++)
                h[i] = (byte)getSmallModFreeze3(h[i] + sign * f[i]);
            for (i = 0; i < p + 1; i++)
                r[i] = (byte)getSmallModFreeze3(r[i] + sign * v[i]);

            for (i = 0; i < p; i++)
                h[i] = h[i+1];
            h[p] = 0;
        }

        sign = f[0];
        for (i = 0; i < p; i++)
            ginv[i] = (byte)(sign * v[p - 1 - i]);

        return (delta == 0);
    }

    protected static void minmax(int[] L, int x, int y)
    {
        int xi = L[x];
        int yi = L[y];
        int xy = xi ^ yi;
        int c = yi - xi;
        c ^= xy & (c ^ yi ^ 0x80000000);
        c = c >>> 31;
        c = -c;
        c &= xy;
        L[x] = xi ^ c;
        L[y] = yi ^ c;
    }

    protected static void cryptoSort(int[] L, int p)
    {
        int top, a, b, i;

        if (p < 2)
          return;

        top = 1;
        while (top < p - top)
          top += top;

        for (a = top; a > 0; a = a >>> 1)
        {
            for (i = 0; i < p - a; i++)
                if ((i & a) == 0)
                    minmax(L, i, i + a);
            for (b = top; b > a; b = b >>> 1)
                for (i = 0; i < p - b; i++)
                    if ((i & a) == 0)
                        minmax(L, i + a, i + b);
        }
    }

    protected static void sortGenerateShortPolynomial(byte[] f, int[] L, int p, int w)
    {
        for (int i = 0; i < w; i++)
            L[i] = L[i] & -2;
        for (int i = w; i < p; i++)
            L[i] = (L[i] & -3) | 1;
        cryptoSort(L, p);
        for (int i = 0; i < p; i++)
            f[i] = (byte)((L[i] & 3) - 1);
    }

    protected static void getRandomShortPolynomial(SecureRandom random, byte[] f, int p, int w)
    {
        int[] L = new int[p];
        getRandomUnsignedIntegers(random, L);
        sortGenerateShortPolynomial(f, L, p, w);
    }

    protected static int getInverseInRQ(int x, int q)
    {
        // x^(q - 2) by square-and-multiply: the exponent is public, so the sequence of operations depends on q alone
        long barrett = getBarrettFactor(q);
        int e = q - 2, bit = 0;
        while ((e >>> bit) > 1)
            bit++;

        int ai = x;
        while (--bit >= 0)
        {
            ai = getModFreeze(ai * ai, q, barrett);
            if (((e >>> bit) & 1) != 0)
            {
                ai = getModFreeze(ai * x, q, barrett);
            }
        }
        return ai;
    }

    protected static void getOneThirdInverseInRQ(short[] finv3, byte[] f, int p, int q)
    {
        short[] h = new short[p + 1];
        short[] g = new short[p + 1];
        short[] r = new short[p + 1];
        short[] v = new short[p + 1];
        int loop, delta, scale, swap, h0, g0, t, i;
        long barrett = getBarrettFactor(q);

        r[0] = (short)getInverseInRQ(3, q);
        h[0] = 1;
        h[p - 1] = -1;
        h[p] = -1;
        for (i = 0; i < p; i++)
            g[p - 1 - i] = f[i];

        g[p] = 0;
        delta = 1;

        for (loop = 0; loop < (2 * p) - 1; loop++)
        {
            System.arraycopy(v, 0, v, 1, p);
            v[0] = 0;

            swap = checkLessThanZero(-delta) & checkNotEqualToZero(g[0]);
            delta ^= swap & (delta ^ -delta);
            delta += 1;

            for (i = 0; i < p + 1; i++)
            {
                t = swap & (h[i] ^ g[i]);
                h[i] ^= t;
                g[i] ^= t;
                t = swap & (v[i] ^ r[i]);
                v[i] ^= t;
                r[i] ^= t;
            }

            h0 = h[0];
            g0 = g[0];
            for (i = 0; i < p + 1; i++)
                g[i] = (short)getModFreeze((h0 * g[i]) - (g0 * h[i]), q, barrett);
            for (i = 0; i < p + 1; i++)
                r[i] = (short)getModFreeze((h0 * r[i]) - (g0 * v[i]), q, barrett);

            for (i = 0; i < p; i++)
                g[i] = g[i+1];
            g[p] = 0;
        }

        scale = getInverseInRQ(h[0], q);
        for (i = 0; i < p; i++)
            finv3[i] = (short)getModFreeze(scale * v[p - 1 - i], q, barrett);
    }

    private static final int KARATSUBA_THRESHOLD = 32;

    /**
     * Return the length the Karatsuba recursion runs at for degree p: the smallest c * 2^k >= p with
     * c <= KARATSUBA_THRESHOLD, so that every level splits evenly. The operands are padded with zeros to it.
     */
    private static int getKaratsubaLength(int p)
    {
        int k = 0;
        while (((p - 1) >> k) + 1 > KARATSUBA_THRESHOLD)
            k++;
        return (((p - 1) >> k) + 1) << k;
    }

    /**
     * r[rOff .. rOff + 2n - 2] = a * b for operands of length n = c * 2^k, using 4n words of t from tOff as scratch.
     * The control flow depends on n alone. Each level at most doubles the bounds on the operands' coefficients, so
     * for |a| <= A and |b| <= B every intermediate value is at most n * 2^k * A * B in magnitude.
     */
    private static void karatsuba(int[] a, int aOff, int[] b, int bOff, int n, int[] r, int rOff, int[] t, int tOff)
    {
        if (n <= KARATSUBA_THRESHOLD)
        {
            for (int i = 0; i < 2 * n - 1; i++)
            {
                r[rOff + i] = 0;
            }
            for (int i = 0; i < n; i++)
            {
                int ai = a[aOff + i];
                for (int j = 0; j < n; j++)
                {
                    r[rOff + i + j] += ai * b[bOff + j];
                }
            }
            return;
        }

        int m = n >>> 1;

        // z0 = a0 * b0 and z2 = a1 * b1, straight into place
        karatsuba(a, aOff, b, bOff, m, r, rOff, t, tOff);
        karatsuba(a, aOff + m, b, bOff + m, m, r, rOff + 2 * m, t, tOff);
        r[rOff + 2 * m - 1] = 0;

        // z1 = (a0 + a1) * (b0 + b1) - z0 - z2, completed before it is added in, since it overlaps z0 and z2
        int sa = tOff, sb = tOff + m, z1 = tOff + 2 * m;
        for (int i = 0; i < m; i++)
        {
            t[sa + i] = a[aOff + i] + a[aOff + m + i];
            t[sb + i] = b[bOff + i] + b[bOff + m + i];
        }
        karatsuba(t, sa, t, sb, m, t, z1, t, z1 + 2 * m - 1);
        for (int i = 0; i < 2 * m - 1; i++)
        {
            t[z1 + i] -= r[rOff + i] + r[rOff + 2 * m + i];
        }
        for (int i = 0; i < 2 * m - 1; i++)
        {
            r[rOff + m + i] += t[z1 + i];
        }
    }

    /**
     * Return the exact product of a and b, both of degree < p and zero-padded to getKaratsubaLength(p), reduced
     * modulo x^p - x - 1, in its first p words.
     * <p>
     * One factor is always reduced, |coefficients| <= (q - 1) / 2, and the other small: in {-1, 0, 1}, or up to 2
     * from a decoded small polynomial. The recursion's intermediates are then below n * 2^k * ((q - 1) / 2) * 2,
     * at most 1280 * 64 * 3939 * 2 < 2^30 (sntrup1277), and the reduced coefficients below 3 * p * ((q - 1) / 2) * 2,
     * so int arithmetic is exact for every parameter set and each coefficient is reduced modulo q (or 3) only once.
     */
    private static int[] getProductModXpX1(int[] a, int[] b, int p)
    {
        int n = a.length;
        int[] fg = new int[2 * n - 1];
        karatsuba(a, 0, b, 0, n, fg, 0, new int[4 * n], 0);

        // x^p = x + 1
        for (int i = p + p - 2; i >= p; i--)
        {
            fg[i - p] += fg[i];
            fg[i - p + 1] += fg[i];
        }
        return fg;
    }

    protected static void multiplicationInRQ(short[] h, short[] finv3, byte[] g, int p, int q)
    {
        int n = getKaratsubaLength(p);
        int[] a = new int[n];
        int[] b = new int[n];
        for (int i = 0; i < p; i++)
        {
            a[i] = finv3[i];
            b[i] = g[i];
        }

        int[] fg = getProductModXpX1(a, b, p);

        long barrett = getBarrettFactor(q);
        for (int i = 0; i < p; i++)
        {
            h[i] = (short)getModFreeze(fg[i], q, barrett);
        }
    }

    /*
     * The reference's Encode and Decode handle a list of values, each with its own modulus. Each level combines
     * neighbouring values in pairs, takes bytes from the bottom of each pair's combined value while its combined
     * modulus is at least 16384, and leaves the rest to the next level, carrying an unpaired last value over
     * unchanged. Here all the moduli are equal at the top level, and pairing keeps them equal except for the last
     * (only the last pair, or the unpaired last value, involves it), so a level is described by its count n, the
     * common modulus m and the last value's modulus mLast.
     */

    /**
     * Return the number of bytes taken from the bottom of a pair's combined value, for combined modulus mm.
     */
    private static int getPairBytes(int mm)
    {
        int bytes = 0;
        while (mm >= 16384)
        {
            mm = (mm + 255) >>> 8;
            bytes++;
        }
        return bytes;
    }

    /**
     * Return the modulus of what remains of a pair's combined value once getPairBytes(mm) bytes are taken from it.
     */
    private static int getPairModulus(int mm)
    {
        while (mm >= 16384)
        {
            mm = (mm + 255) >>> 8;
        }
        return mm;
    }

    /**
     * Encode n values from R into out: the last below mLast, the others below m. Overwrites R. The sequence of
     * operations depends only on n, m and mLast.
     */
    private static void encode(byte[] out, short[] R, int n, int m, int mLast)
    {
        int pos = 0;

        while (n > 1)
        {
            int pairs = n >>> 1;
            boolean lastPaired = (n & 1) == 0;

            int b = getPairBytes(m * m), m2 = getPairModulus(m * m);
            int bLast = 0, m2Last = mLast;
            if (lastPaired)
            {
                bLast = getPairBytes(m * mLast);
                m2Last = getPairModulus(m * mLast);
            }

            // pair j's combined value replaces R[j], which has been read by then
            for (int j = 0; j < pairs; j++)
            {
                int bj = (lastPaired && j == pairs - 1) ? bLast : b;

                int r = R[2 * j] + R[2 * j + 1] * m;
                for (int k = 0; k < bj; k++)
                {
                    out[pos++] = (byte)r;
                    r >>>= 8;
                }
                R[j] = (short)r;
            }

            if (!lastPaired)
            {
                R[pairs] = R[n - 1];
            }

            n = pairs + (n & 1);
            m = m2;
            mLast = m2Last;
        }

        int r0 = R[0];
        while (mLast > 1)
        {
            out[pos++] = (byte)r0;
            r0 >>>= 8;
            mLast = (mLast + 255) >>> 8;
        }
    }

    protected static void getEncodedPolynomial(byte[] enc, short[] h, int p, int q)
    {
        short[] R = new short[p];

        for (int i = 0; i < p; i++)
            R[i] = (short)(h[i] + ((q - 1) / 2));

        encode(enc, R, p, q, q);
    }

    protected static void getEncodedSmallPolynomial(byte[] encSP, byte[] sp, int p)
    {
        byte x;
        int spIndex = 0;
        int encSPIndex = 0;
        for (int i = 0; i < p / 4; i++)
        {
            x = (byte)(sp[spIndex++] + 1);
            x += (byte)(sp[spIndex++] + 1) << 2;
            x += (byte)(sp[spIndex++] + 1) << 4;
            x += (byte)(sp[spIndex++] + 1) << 6;
            encSP[encSPIndex++] = x;
        }
        encSP[encSPIndex] = (byte)(sp[spIndex] + 1);
    }

    private static void generateAES256CTRStream(byte[] in, byte[] out, byte[] nonce, byte[] key)
    {
        StreamCipher cipher = SICBlockCipher.newInstance(AESEngine.newInstance());
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
        cipher.processBytes(in, 0, out.length, out, 0);
    }

    protected static void expand(int[] L, byte[] k)
    {
        byte[] aesInput = new byte[L.length * 4];
        byte[] aesOutput = new byte[L.length * 4];
        byte[] nonce = new byte[16];
        generateAES256CTRStream(aesInput, aesOutput, nonce, k);
        for (int i = 0; i < L.length; i++)
            L[i] = (bToUnsignedInt(aesOutput[i * 4])
                    + (bToUnsignedInt(aesOutput[(i * 4) + 1]) << 8)
                    + (bToUnsignedInt(aesOutput[(i * 4) + 2]) << 16)
                    + (bToUnsignedInt(aesOutput[(i * 4) + 3]) << 24));
    }

    protected static void generatePolynomialInRQFromSeed(short[] G, byte[] seed, int p, int q)
    {
        int[] L = new int[p];
        expand(L, seed);

        for (int i = 0; i < p; i++)
            G[i] = (short)((int)(iToUnsignedLong(L[i]) % q) - ((q - 1) / 2));
    }

    protected static void roundPolynomial(short[] out, short[] in)
    {
        for (int i = 0; i < out.length; i++)
            out[i] = (short)(in[i] - getModFreeze(in[i], 3, BARRETT_3));
    }

    protected static void getRoundedEncodedPolynomial(byte[] out, short[] in, int p, int q)
    {
        short[] R = new short[p];

        for (int i = 0; i < p; i++)
            R[i] = (short)(((in[i] + ((q - 1) / 2)) * 10923) >>> 15);

        int m = (q + 2) / 3;
        encode(out, R, p, m, m);
    }

    protected static byte[] getHashWithPrefix(byte[] prefix, byte[] hashInput)
    {
        byte[] hash = new byte[64];
        byte[] input = new byte[prefix.length + hashInput.length];
        System.arraycopy(prefix, 0, input, 0, prefix.length);
        System.arraycopy(hashInput, 0, input, prefix.length, hashInput.length);
        SHA512Digest hashDigest = new SHA512Digest();
        hashDigest.update(input, 0, input.length);
        hashDigest.doFinal(hash, 0);
        return hash;
    }

    /**
     * Decode n values from s at sOff into out[0 .. n - 1]: the last below mLast, the others below m. The input is
     * public (a public key or ciphertext), so the divisions are fine. A truncated input fails with an
     * ArrayIndexOutOfBoundsException, since the last byte of an encoding is always read.
     */
    private static void decode(short[] out, byte[] s, int sOff, int n, int m, int mLast)
    {
        if (n == 1)
        {
            if (mLast == 1)
                out[0] = 0;
            else if (mLast <= 256)
                out[0] = (short)(bToUnsignedInt(s[sOff]) % mLast);
            else
                out[0] = (short)((bToUnsignedInt(s[sOff]) | (bToUnsignedInt(s[sOff + 1]) << 8)) % mLast);
            return;
        }

        int pairs = n >>> 1;
        boolean lastPaired = (n & 1) == 0;

        int b = getPairBytes(m * m), m2 = getPairModulus(m * m);
        int bLast = 0, m2Last = mLast;
        if (lastPaired)
        {
            bLast = getPairBytes(m * mLast);
            m2Last = getPairModulus(m * mLast);
        }

        // The pairs' bottom bytes come first, then the next level's encoding, which is decoded into the start of out
        // and then expanded in place, from the end down so that no value is overwritten before it is read
        int bottomBytes = (lastPaired ? pairs - 1 : pairs) * b + bLast;
        decode(out, s, sOff + bottomBytes, pairs + (n & 1), m2, m2Last);

        if (!lastPaired)
        {
            out[n - 1] = out[pairs];
        }

        for (int j = pairs - 1; j >= 0; j--)
        {
            boolean last = lastPaired && j == pairs - 1;
            int bj = last ? bLast : b;
            int bOff = sOff + j * b;

            // below 2^14 * 2^16, since every decoded value is reduced
            int r = out[j] << (8 * bj);
            for (int k = 0; k < bj; k++)
            {
                r |= bToUnsignedInt(s[bOff + k]) << (8 * k);
            }

            out[2 * j] = (short)(r % m);
            // the reduction is only needed for invalid inputs
            out[2 * j + 1] = (short)((r / m) % (last ? mLast : m));
        }
    }

    protected static void getDecodedPolynomial(short[] h, byte[] enc, int p, int q)
    {
        decode(h, enc, 0, p, q, q);

        for (int i = 0; i < p; i++)
            h[i] = (short)(h[i] - ((q - 1) / 2));
    }

    protected static void getRandomInputs(SecureRandom random, byte[] r)
    {
        byte[] seed = new byte[r.length / 8];
        random.nextBytes(seed);

        for (int i = 0; i < r.length; i++)
            r[i] = (byte)(1 & (seed[i >>> 3] >>> (i & 7)));
    }

    protected static void getEncodedInputs(byte[] out, byte[] in)
    {
        for (int i = 0; i < in.length; i++)
            out[i >>> 3] |= in[i] << (i & 7);
    }

    protected static void getRoundedDecodedPolynomial(short[] h, byte[] enc, int p, int q)
    {
        int m = (q + 2) / 3;
        decode(h, enc, 0, p, m, m);

        for (int i = 0; i < p; i++)
            h[i] = (short)((h[i] * 3) - ((q - 1) / 2));
    }

    protected static void top(byte[] out, short[] bA, byte[] r, int q, int tau0, int tau1)
    {
        long barrett = getBarrettFactor(q);
        for (int i = 0; i < out.length; i++)
            out[i] = (byte)((tau1 * (getModFreeze(bA[i] + r[i] * ((q - 1) / 2), q, barrett) + tau0) + 16384) >>> 15);
    }

    protected static void getTopEncodedPolynomial(byte[] out, byte[] in)
    {
        for (int i = 0; i < out.length; i++)
            out[i] = (byte)(in[2 * i] + (in[(2 * i) + 1] << 4));
    }

    protected static void getDecodedSmallPolynomial(byte[] sp, byte[] encSP, int p)
    {
        byte x;
        int spIndex = 0;
        int encSPIndex = 0;

        for (int i = 0; i < p / 4; i++)
        {
            x = encSP[encSPIndex++];
            sp[spIndex++] = (byte)((bToUnsignedInt(x) & 3) - 1); x >>>= 2;
            sp[spIndex++] = (byte)((bToUnsignedInt(x) & 3) - 1); x >>>= 2;
            sp[spIndex++] = (byte)((bToUnsignedInt(x) & 3) - 1); x >>>= 2;
            sp[spIndex++] = (byte)((bToUnsignedInt(x) & 3) - 1);
        }

        x = encSP[encSPIndex];
        sp[spIndex] = (byte)((bToUnsignedInt(x) & 3) - 1);
    }

    protected static void scalarMultiplicationInRQ(short[] out, short[] in, int scalar, int q)
    {
        long barrett = getBarrettFactor(q);
        for (int i = 0; i < in.length; i++)
            out[i] = (short)getModFreeze(scalar * in[i], q, barrett);
    }

    protected static void transformRQToR3(byte[] out, short[] in)
    {
        for (int i = 0; i < in.length; i++)
            out[i] = (byte)getModFreeze(in[i], 3, BARRETT_3);
    }

    protected static void multiplicationInR3(byte[] h, byte[] finv3, byte[] g, int p)
    {
        int n = getKaratsubaLength(p);
        int[] a = new int[n];
        int[] b = new int[n];
        for (int i = 0; i < p; i++)
        {
            a[i] = finv3[i];
            b[i] = g[i];
        }

        int[] fg = getProductModXpX1(a, b, p);

        for (int i = 0; i < p; i++)
        {
            h[i] = (byte)getModFreeze(fg[i], 3, BARRETT_3);
        }
    }

    protected static void checkForSmallPolynomial(byte[] r, byte[] ev, int p, int w)
    {
        int weight = 0;
        for (int i = 0; i != ev.length; i++)
        {
            weight += ev[i] & 1;
        }

        int mask = checkNotEqualToZero(weight - w);
        for (int i = 0; i < w; i++)
            r[i] = (byte)(((ev[i] ^ 1) & ~mask) ^ 1);
        for (int i = w; i < p; i++)
            r[i] = (byte)(ev[i] & ~mask);
    }

    /**
     * Return 0 if a and b are equal and -1 otherwise, without branching on their contents.
     */
    protected static int getCiphertextDiffMask(byte[] a, byte[] b)
    {
        int diff = a.length ^ b.length;
        for (int i = 0; i < a.length && i < b.length; i++)
            diff |= a[i] ^ b[i];
        return checkNotEqualToZero(diff);
    }

    protected static void updateDiffMask(byte[] encR, byte[] rho, int mask)
    {
        for (int i = 0; i < encR.length; i++)
            encR[i] ^= mask & (encR[i] ^ rho[i]);
    }

    protected static void getTopDecodedPolynomial(byte[] out, byte[] in)
    {
        for (int i = 0; i < in.length; i++)
        {
            out[2 * i] = (byte)(in[i] & 15);
            out[(2 * i) + 1] = (byte)(in[i] >>> 4);
        }
    }

    protected static void right(byte[] out, short[] aB, byte[] T, int q, int w, int tau2, int tau3)
    {
        long barrett = getBarrettFactor(q);
        for (int i = 0; i < out.length; i++)
            out[i] = (byte)(-checkLessThanZero(getModFreeze(getModFreeze((tau3 * T[i]) - tau2, q, barrett) - aB[i] + (4 * w) + 1, q, barrett)));
    }

    private static int checkLessThanZero(int x)
    {
        return -(int)(x >>> 31);
    }

    private static int checkNotEqualToZero(int x)
    {
        long l = iToUnsignedLong(x);
        l = -l;
        return -(int)(l >>> 63);
    }

    static int bToUnsignedInt(byte b)
    {
        return b & 0xff;
    }

    static long iToUnsignedLong(int i)
    {
        return i & 0xffffffffL;
    }
}
