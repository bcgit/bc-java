package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.SavableDigest;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;


/**
 * FIPS 180-2 implementation of SHA-256.
 *
 * <pre>
 *         block  word  digest
 * SHA-1   512    32    160
 * SHA-256 512    32    256
 * SHA-384 1024   64    384
 * SHA-512 1024   64    512
 * </pre>
 */
public class SHA256Digest
    extends GeneralDigest
    implements SavableDigest
{
    private static final int    DIGEST_LENGTH = 32;

    private int     H1, H2, H3, H4, H5, H6, H7, H8;

    private int[]   X = new int[16];
    private int     xOff;

    public static SavableDigest newInstance()
    {
        return new SHA256Digest();
    }

    public static SavableDigest newInstance(CryptoServicePurpose purpose)
    {
        return new SHA256Digest(purpose);
    }

    public static SavableDigest newInstance(Digest digest)
    {
        if (digest instanceof SHA256Digest)
        {
            return new SHA256Digest((SHA256Digest) digest);
        }

        throw new IllegalArgumentException("receiver digest not available for input type " + (digest != null ? digest.getClass().getName() : "null"));
    }

    public static SavableDigest newInstance(byte[] encoded)
    {
        return new SHA256Digest(encoded);
    }

    /**
     * Standard constructor
     */
    public SHA256Digest()
    {
        this(CryptoServicePurpose.ANY);
    }

    /**
     * Standard constructor, with purpose
     */
    public SHA256Digest(CryptoServicePurpose purpose)
    {
        super(purpose);

        CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());

        reset();
    }

    /**
     * Copy constructor.  This will copy the state of the provided
     * message digest.
     */
    public SHA256Digest(SHA256Digest t)
    {
        super(t);

        copyIn(t);
    }

    private void copyIn(SHA256Digest t)
    {
        super.copyIn(t);

        H1 = t.H1;
        H2 = t.H2;
        H3 = t.H3;
        H4 = t.H4;
        H5 = t.H5;
        H6 = t.H6;
        H7 = t.H7;
        H8 = t.H8;

        System.arraycopy(t.X, 0, X, 0, t.X.length);
        xOff = t.xOff;
    }

    /**
     * State constructor - create a digest initialised with the state of a previous one.
     *
     * @param encodedState the encoded state from the originating digest.
     */
    public SHA256Digest(byte[] encodedState)
    {
        super(encodedState);

        H1 = Pack.bigEndianToInt(encodedState, 16);
        H2 = Pack.bigEndianToInt(encodedState, 20);
        H3 = Pack.bigEndianToInt(encodedState, 24);
        H4 = Pack.bigEndianToInt(encodedState, 28);
        H5 = Pack.bigEndianToInt(encodedState, 32);
        H6 = Pack.bigEndianToInt(encodedState, 36);
        H7 = Pack.bigEndianToInt(encodedState, 40);
        H8 = Pack.bigEndianToInt(encodedState, 44);

        xOff = Pack.bigEndianToInt(encodedState, 48);
        for (int i = 0; i != xOff; i++)
        {
            X[i] = Pack.bigEndianToInt(encodedState, 52 + (i * 4));
        }
    }


    public String getAlgorithmName()
    {
        return "SHA-256";
    }

    public int getDigestSize()
    {
        return DIGEST_LENGTH;
    }

    protected void processWord(
        byte[]  in,
        int     inOff)
    {
        X[xOff] = Pack.bigEndianToInt(in, inOff);

        if (++xOff == 16)
        {
            processBlock();
        }
    }

    protected void processLength(
        long    bitLength)
    {
        if (xOff > 14)
        {
            processBlock();
        }

        X[14] = (int)(bitLength >>> 32);
        X[15] = (int)(bitLength & 0xffffffff);
    }

    public int doFinal(byte[] out, int outOff)
    {
        finish();

        Pack.intToBigEndian(H1, out, outOff);
        Pack.intToBigEndian(H2, out, outOff + 4);
        Pack.intToBigEndian(H3, out, outOff + 8);
        Pack.intToBigEndian(H4, out, outOff + 12);
        Pack.intToBigEndian(H5, out, outOff + 16);
        Pack.intToBigEndian(H6, out, outOff + 20);
        Pack.intToBigEndian(H7, out, outOff + 24);
        Pack.intToBigEndian(H8, out, outOff + 28);

        reset();

        return DIGEST_LENGTH;
    }

    /**
     * reset the chaining variables
     */
    public void reset()
    {
        super.reset();

        /* SHA-256 initial hash value
         * The first 32 bits of the fractional parts of the square roots
         * of the first eight prime numbers
         */

        H1 = 0x6a09e667;
        H2 = 0xbb67ae85;
        H3 = 0x3c6ef372;
        H4 = 0xa54ff53a;
        H5 = 0x510e527f;
        H6 = 0x9b05688c;
        H7 = 0x1f83d9ab;
        H8 = 0x5be0cd19;

        xOff = 0;
        for (int i = 0; i != X.length; i++)
        {
            X[i] = 0;
        }
    }

    protected void processBlock()
    {
        int[] X = this.X;

        // The message schedule lives in 16 rotating locals instead of a 64/80-word array: no bounds
        // checks or memory traffic for the expansion, and the array only ever holds the 16 input words.
        int x00 = X[0], x01 = X[1], x02 = X[2], x03 = X[3];
        int x04 = X[4], x05 = X[5], x06 = X[6], x07 = X[7];
        int x08 = X[8], x09 = X[9], x10 = X[10], x11 = X[11];
        int x12 = X[12], x13 = X[13], x14 = X[14], x15 = X[15];

        int a = H1, b = H2, c = H3, d = H4, e = H5, f = H6, g = H7, h = H8;

        for (int t = 0; ; t += 16)
        {
            h += Sum1(e) + Ch(e, f, g) + K[t] + x00;
            d += h;
            h += Sum0(a) + Maj(a, b, c);

            g += Sum1(d) + Ch(d, e, f) + K[t + 1] + x01;
            c += g;
            g += Sum0(h) + Maj(h, a, b);

            f += Sum1(c) + Ch(c, d, e) + K[t + 2] + x02;
            b += f;
            f += Sum0(g) + Maj(g, h, a);

            e += Sum1(b) + Ch(b, c, d) + K[t + 3] + x03;
            a += e;
            e += Sum0(f) + Maj(f, g, h);

            d += Sum1(a) + Ch(a, b, c) + K[t + 4] + x04;
            h += d;
            d += Sum0(e) + Maj(e, f, g);

            c += Sum1(h) + Ch(h, a, b) + K[t + 5] + x05;
            g += c;
            c += Sum0(d) + Maj(d, e, f);

            b += Sum1(g) + Ch(g, h, a) + K[t + 6] + x06;
            f += b;
            b += Sum0(c) + Maj(c, d, e);

            a += Sum1(f) + Ch(f, g, h) + K[t + 7] + x07;
            e += a;
            a += Sum0(b) + Maj(b, c, d);

            h += Sum1(e) + Ch(e, f, g) + K[t + 8] + x08;
            d += h;
            h += Sum0(a) + Maj(a, b, c);

            g += Sum1(d) + Ch(d, e, f) + K[t + 9] + x09;
            c += g;
            g += Sum0(h) + Maj(h, a, b);

            f += Sum1(c) + Ch(c, d, e) + K[t + 10] + x10;
            b += f;
            f += Sum0(g) + Maj(g, h, a);

            e += Sum1(b) + Ch(b, c, d) + K[t + 11] + x11;
            a += e;
            e += Sum0(f) + Maj(f, g, h);

            d += Sum1(a) + Ch(a, b, c) + K[t + 12] + x12;
            h += d;
            d += Sum0(e) + Maj(e, f, g);

            c += Sum1(h) + Ch(h, a, b) + K[t + 13] + x13;
            g += c;
            c += Sum0(d) + Maj(d, e, f);

            b += Sum1(g) + Ch(g, h, a) + K[t + 14] + x14;
            f += b;
            b += Sum0(c) + Maj(c, d, e);

            a += Sum1(f) + Ch(f, g, h) + K[t + 15] + x15;
            e += a;
            a += Sum0(b) + Maj(b, c, d);

            if (t == 48)
                break;

            // W[t+16+j] = sigma1(W[t+14+j]) + W[t+9+j] + sigma0(W[t+1+j]) + W[t+j]; wrapped indices refer to
            // words already updated in this pass, which is exactly the required schedule.
            x00 += Theta1(x14) + x09 + Theta0(x01);
            x01 += Theta1(x15) + x10 + Theta0(x02);
            x02 += Theta1(x00) + x11 + Theta0(x03);
            x03 += Theta1(x01) + x12 + Theta0(x04);
            x04 += Theta1(x02) + x13 + Theta0(x05);
            x05 += Theta1(x03) + x14 + Theta0(x06);
            x06 += Theta1(x04) + x15 + Theta0(x07);
            x07 += Theta1(x05) + x00 + Theta0(x08);
            x08 += Theta1(x06) + x01 + Theta0(x09);
            x09 += Theta1(x07) + x02 + Theta0(x10);
            x10 += Theta1(x08) + x03 + Theta0(x11);
            x11 += Theta1(x09) + x04 + Theta0(x12);
            x12 += Theta1(x10) + x05 + Theta0(x13);
            x13 += Theta1(x11) + x06 + Theta0(x14);
            x14 += Theta1(x12) + x07 + Theta0(x15);
            x15 += Theta1(x13) + x08 + Theta0(x00);
        }

        H1 += a;
        H2 += b;
        H3 += c;
        H4 += d;
        H5 += e;
        H6 += f;
        H7 += g;
        H8 += h;

        //
        // reset the offset and clean out the word buffer.
        //
        xOff = 0;
        for (int i = 0; i < 16; i++)
        {
            X[i] = 0;
        }
    }

    private static int Ch(int x, int y, int z)
    {
        //return (x & y) ^ (z & ~x);
        return z ^ (x & (y ^ z));
    }

    private static int Maj(int x, int y, int z)
    {
        //return (x & y) ^ (x & z) ^ (y & z);
        return (x & y) | (z & (x ^ y));
    }

    private static int Sum0(int x)
    {
        return ((x >>> 2) | (x << 30)) ^ ((x >>> 13) | (x << 19)) ^ ((x >>> 22) | (x << 10));
    }

    private static int Sum1(int x)
    {
        return ((x >>> 6) | (x << 26)) ^ ((x >>> 11) | (x << 21)) ^ ((x >>> 25) | (x << 7));
    }

    private static int Theta0(int x)
    {
        return ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
    }

    private static int Theta1(int x)
    {
        return ((x >>> 17) | (x << 15)) ^ ((x >>> 19) | (x << 13)) ^ (x >>> 10);
    }

    /**
     * SHA-256 Constants (represent the first 32 bits of the fractional parts of the cube roots of the first sixty-four
     * prime numbers)
     */
    static final int K[] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    public Memoable copy()
    {
        return new SHA256Digest(this);
    }

    public void reset(Memoable other)
    {
        SHA256Digest d = (SHA256Digest)other;

        copyIn(d);
    }

    public byte[] getEncodedState()
    {
        byte[] state = new byte[52 + xOff * 4 + 1];

        super.populateState(state);

        Pack.intToBigEndian(H1, state, 16);
        Pack.intToBigEndian(H2, state, 20);
        Pack.intToBigEndian(H3, state, 24);
        Pack.intToBigEndian(H4, state, 28);
        Pack.intToBigEndian(H5, state, 32);
        Pack.intToBigEndian(H6, state, 36);
        Pack.intToBigEndian(H7, state, 40);
        Pack.intToBigEndian(H8, state, 44);
        Pack.intToBigEndian(xOff, state, 48);

        for (int i = 0; i != xOff; i++)
        {
            Pack.intToBigEndian(X[i], state, 52 + (i * 4));
        }

        state[state.length - 1] = (byte)purpose.getCode();

        return state;
    }

    protected CryptoServiceProperties cryptoServiceProperties()
    {
        return Utils.getDefaultProperties(this, 256, purpose);
    }
}

