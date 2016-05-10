package com.github.gv2011.bcasn.crypto.digests;


import com.github.gv2011.bcasn.util.Memoable;

/**
 * implementation of RIPEMD128
 */
public class RIPEMD128Digest
    extends GeneralDigest
{
    private static final int DIGEST_LENGTH = 16;

    private int H0, H1, H2, H3; // IV's

    private int[] X = new int[16];
    private int xOff;

    /**
     * Standard constructor
     */
    public RIPEMD128Digest()
    {
        reset();
    }

    /**
     * Copy constructor.  This will copy the state of the provided
     * message digest.
     */
    public RIPEMD128Digest(RIPEMD128Digest t)
    {
        super(t);

        copyIn(t);
    }

    private void copyIn(RIPEMD128Digest t)
    {
        super.copyIn(t);

        H0 = t.H0;
        H1 = t.H1;
        H2 = t.H2;
        H3 = t.H3;

        System.arraycopy(t.X, 0, X, 0, t.X.length);
        xOff = t.xOff;
    }

    public String getAlgorithmName()
    {
        return "RIPEMD128";
    }

    public int getDigestSize()
    {
        return DIGEST_LENGTH;
    }

    protected void processWord(
        byte[] in,
        int inOff)
    {
        X[xOff++] = (in[inOff] & 0xff) | ((in[inOff + 1] & 0xff) << 8)
            | ((in[inOff + 2] & 0xff) << 16) | ((in[inOff + 3] & 0xff) << 24); 

        if (xOff == 16)
        {
            processBlock();
        }
    }

    protected void processLength(
        long bitLength)
    {
        if (xOff > 14)
        {
        processBlock();
        }

        X[14] = (int)(bitLength & 0xffffffff);
        X[15] = (int)(bitLength >>> 32);
    }

    private void unpackWord(
        int word,
        byte[] out,
        int outOff)
    {
        out[outOff]     = (byte)word;
        out[outOff + 1] = (byte)(word >>> 8);
        out[outOff + 2] = (byte)(word >>> 16);
        out[outOff + 3] = (byte)(word >>> 24);
    }

    public int doFinal(
        byte[] out,
        int outOff)
    {
        finish();

        unpackWord(H0, out, outOff);
        unpackWord(H1, out, outOff + 4);
        unpackWord(H2, out, outOff + 8);
        unpackWord(H3, out, outOff + 12);

        reset();

        return DIGEST_LENGTH;
    }

    /**
    * reset the chaining variables to the IV values.
    */
    public void reset()
    {
        super.reset();

        H0 = 0x67452301;
        H1 = 0xefcdab89;
        H2 = 0x98badcfe;
        H3 = 0x10325476;

        xOff = 0;

        for (int i = 0; i != X.length; i++)
        {
            X[i] = 0;
        }
    }

    /*
     * rotate int x left n bits.
     */
    private int RL(
        int x,
        int n)
    {
        return (x << n) | (x >>> (32 - n));
    }

    /*
     * f1,f2,f3,f4 are the basic RIPEMD128 functions.
     */

    /*
     * F
     */
    private int f1(
        int x,
        int y,
        int z)
    {
        return x ^ y ^ z;
    }

    /*
     * G
     */
    private int f2(
        int x,
        int y,
        int z)
    {
        return (x & y) | (~x & z);
    }

    /*
     * H
     */
    private int f3(
        int x,
        int y,
        int z)
    {
        return (x | ~y) ^ z;
    }

    /*
     * I
     */
    private int f4(
        int x,
        int y,
        int z)
    {
        return (x & z) | (y & ~z);
    }

    private int F1(
        int a,
        int b,
        int c,
        int d,
        int x,
        int s)
    {
        return RL(a + f1(b, c, d) + x, s);
    }

    private int F2(
        int a,
        int b,
        int c,
        int d,
        int x,
        int s)
    {
        return RL(a + f2(b, c, d) + x + 0x5a827999, s);
    }

    private int F3(
        int a,
        int b,
        int c,
        int d,
        int x,
        int s)
    {
        return RL(a + f3(b, c, d) + x + 0x6ed9eba1, s);
    }

    private int F4(
        int a,
        int b,
        int c,
        int d,
        int x,
        int s)
    {
        return RL(a + f4(b, c, d) + x + 0x8f1bbcdc, s);
    }

    private int FF1(
        int a,
        int b,
        int c,
        int d,
        int x,
        int s)
    {
        return RL(a + f1(b, c, d) + x, s);
    }

    private int FF2(
        int a,
        int b,
        int c,
        int d,
        int x,
        int s)
    {
      return RL(a + f2(b, c, d) + x + 0x6d703ef3, s);
    }

    private int FF3(
        int a,
        int b,
        int c,
        int d,
        int x,
        int s)
    {
      return RL(a + f3(b, c, d) + x + 0x5c4dd124, s);
    }

    private int FF4(
        int a,
        int b,
        int c,
        int d,
        int x,
        int s)
    {
      return RL(a + f4(b, c, d) + x + 0x50a28be6, s);
    }

    protected void processBlock()
    {
        int a, aa;
        int b, bb;
        int c, cc;
        int d, dd;

        a = aa = H0;
        b = bb = H1;
        c = cc = H2;
        d = dd = H3;

        //
        // Round 1
        //
        a = F1(a, b, c, d, X[ 0], 11);
        d = F1(d, a, b, c, X[ 1], 14);
        c = F1(c, d, a, b, X[ 2], 15);
        b = F1(b, c, d, a, X[ 3], 12);
        a = F1(a, b, c, d, X[ 4],  5);
        d = F1(d, a, b, c, X[ 5],  8);
        c = F1(c, d, a, b, X[ 6],  7);
        b = F1(b, c, d, a, X[ 7],  9);
        a = F1(a, b, c, d, X[ 8], 11);
        d = F1(d, a, b, c, X[ 9], 13);
        c = F1(c, d, a, b, X[10], 14);
        b = F1(b, c, d, a, X[11], 15);
        a = F1(a, b, c, d, X[12],  6);
        d = F1(d, a, b, c, X[13],  7);
        c = F1(c, d, a, b, X[14],  9);
        b = F1(b, c, d, a, X[15],  8);

        //
        // Round 2
        //
        a = F2(a, b, c, d, X[ 7],  7);
        d = F2(d, a, b, c, X[ 4],  6);
        c = F2(c, d, a, b, X[13],  8);
        b = F2(b, c, d, a, X[ 1], 13);
        a = F2(a, b, c, d, X[10], 11);
        d = F2(d, a, b, c, X[ 6],  9);
        c = F2(c, d, a, b, X[15],  7);
        b = F2(b, c, d, a, X[ 3], 15);
        a = F2(a, b, c, d, X[12],  7);
        d = F2(d, a, b, c, X[ 0], 12);
        c = F2(c, d, a, b, X[ 9], 15);
        b = F2(b, c, d, a, X[ 5],  9);
        a = F2(a, b, c, d, X[ 2], 11);
        d = F2(d, a, b, c, X[14],  7);
        c = F2(c, d, a, b, X[11], 13);
        b = F2(b, c, d, a, X[ 8], 12);

        //
        // Round 3
        //
        a = F3(a, b, c, d, X[ 3], 11);
        d = F3(d, a, b, c, X[10], 13);
        c = F3(c, d, a, b, X[14],  6);
        b = F3(b, c, d, a, X[ 4],  7);
        a = F3(a, b, c, d, X[ 9], 14);
        d = F3(d, a, b, c, X[15],  9);
        c = F3(c, d, a, b, X[ 8], 13);
        b = F3(b, c, d, a, X[ 1], 15);
        a = F3(a, b, c, d, X[ 2], 14);
        d = F3(d, a, b, c, X[ 7],  8);
        c = F3(c, d, a, b, X[ 0], 13);
        b = F3(b, c, d, a, X[ 6],  6);
        a = F3(a, b, c, d, X[13],  5);
        d = F3(d, a, b, c, X[11], 12);
        c = F3(c, d, a, b, X[ 5],  7);
        b = F3(b, c, d, a, X[12],  5);

        //
        // Round 4
        //
        a = F4(a, b, c, d, X[ 1], 11);
        d = F4(d, a, b, c, X[ 9], 12);
        c = F4(c, d, a, b, X[11], 14);
        b = F4(b, c, d, a, X[10], 15);
        a = F4(a, b, c, d, X[ 0], 14);
        d = F4(d, a, b, c, X[ 8], 15);
        c = F4(c, d, a, b, X[12],  9);
        b = F4(b, c, d, a, X[ 4],  8);
        a = F4(a, b, c, d, X[13],  9);
        d = F4(d, a, b, c, X[ 3], 14);
        c = F4(c, d, a, b, X[ 7],  5);
        b = F4(b, c, d, a, X[15],  6);
        a = F4(a, b, c, d, X[14],  8);
        d = F4(d, a, b, c, X[ 5],  6);
        c = F4(c, d, a, b, X[ 6],  5);
        b = F4(b, c, d, a, X[ 2], 12);

        //
        // Parallel round 1
        //
        aa = FF4(aa, bb, cc, dd, X[ 5],  8);
        dd = FF4(dd, aa, bb, cc, X[14],  9);
        cc = FF4(cc, dd, aa, bb, X[ 7],  9);
        bb = FF4(bb, cc, dd, aa, X[ 0], 11);
        aa = FF4(aa, bb, cc, dd, X[ 9], 13);
        dd = FF4(dd, aa, bb, cc, X[ 2], 15);
        cc = FF4(cc, dd, aa, bb, X[11], 15);
        bb = FF4(bb, cc, dd, aa, X[ 4],  5);
        aa = FF4(aa, bb, cc, dd, X[13],  7);
        dd = FF4(dd, aa, bb, cc, X[ 6],  7);
        cc = FF4(cc, dd, aa, bb, X[15],  8);
        bb = FF4(bb, cc, dd, aa, X[ 8], 11);
        aa = FF4(aa, bb, cc, dd, X[ 1], 14);
        dd = FF4(dd, aa, bb, cc, X[10], 14);
        cc = FF4(cc, dd, aa, bb, X[ 3], 12);
        bb = FF4(bb, cc, dd, aa, X[12],  6);

        //
        // Parallel round 2
        //
        aa = FF3(aa, bb, cc, dd, X[ 6],  9);
        dd = FF3(dd, aa, bb, cc, X[11], 13);
        cc = FF3(cc, dd, aa, bb, X[ 3], 15);
        bb = FF3(bb, cc, dd, aa, X[ 7],  7);
        aa = FF3(aa, bb, cc, dd, X[ 0], 12);
        dd = FF3(dd, aa, bb, cc, X[13],  8);
        cc = FF3(cc, dd, aa, bb, X[ 5],  9);
        bb = FF3(bb, cc, dd, aa, X[10], 11);
        aa = FF3(aa, bb, cc, dd, X[14],  7);
        dd = FF3(dd, aa, bb, cc, X[15],  7);
        cc = FF3(cc, dd, aa, bb, X[ 8], 12);
        bb = FF3(bb, cc, dd, aa, X[12],  7);
        aa = FF3(aa, bb, cc, dd, X[ 4],  6);
        dd = FF3(dd, aa, bb, cc, X[ 9], 15);
        cc = FF3(cc, dd, aa, bb, X[ 1], 13);
        bb = FF3(bb, cc, dd, aa, X[ 2], 11);

        //
        // Parallel round 3
        //
        aa = FF2(aa, bb, cc, dd, X[15],  9);
        dd = FF2(dd, aa, bb, cc, X[ 5],  7);
        cc = FF2(cc, dd, aa, bb, X[ 1], 15);
        bb = FF2(bb, cc, dd, aa, X[ 3], 11);
        aa = FF2(aa, bb, cc, dd, X[ 7],  8);
        dd = FF2(dd, aa, bb, cc, X[14],  6);
        cc = FF2(cc, dd, aa, bb, X[ 6],  6);
        bb = FF2(bb, cc, dd, aa, X[ 9], 14);
        aa = FF2(aa, bb, cc, dd, X[11], 12);
        dd = FF2(dd, aa, bb, cc, X[ 8], 13);
        cc = FF2(cc, dd, aa, bb, X[12],  5);
        bb = FF2(bb, cc, dd, aa, X[ 2], 14);
        aa = FF2(aa, bb, cc, dd, X[10], 13);
        dd = FF2(dd, aa, bb, cc, X[ 0], 13);
        cc = FF2(cc, dd, aa, bb, X[ 4],  7);
        bb = FF2(bb, cc, dd, aa, X[13],  5);

        //
        // Parallel round 4
        //
        aa = FF1(aa, bb, cc, dd, X[ 8], 15);
        dd = FF1(dd, aa, bb, cc, X[ 6],  5);
        cc = FF1(cc, dd, aa, bb, X[ 4],  8);
        bb = FF1(bb, cc, dd, aa, X[ 1], 11);
        aa = FF1(aa, bb, cc, dd, X[ 3], 14);
        dd = FF1(dd, aa, bb, cc, X[11], 14);
        cc = FF1(cc, dd, aa, bb, X[15],  6);
        bb = FF1(bb, cc, dd, aa, X[ 0], 14);
        aa = FF1(aa, bb, cc, dd, X[ 5],  6);
        dd = FF1(dd, aa, bb, cc, X[12],  9);
        cc = FF1(cc, dd, aa, bb, X[ 2], 12);
        bb = FF1(bb, cc, dd, aa, X[13],  9);
        aa = FF1(aa, bb, cc, dd, X[ 9], 12);
        dd = FF1(dd, aa, bb, cc, X[ 7],  5);
        cc = FF1(cc, dd, aa, bb, X[10], 15);
        bb = FF1(bb, cc, dd, aa, X[14],  8);

        dd += c + H1;               // final result for H0

        //
        // combine the results
        //
        H1 = H2 + d + aa;
        H2 = H3 + a + bb;
        H3 = H0 + b + cc;
        H0 = dd;

        //
        // reset the offset and clean out the word buffer.
        //
        xOff = 0;
        for (int i = 0; i != X.length; i++)
        {
            X[i] = 0;
        }
    }

    public Memoable copy()
    {
        return new RIPEMD128Digest(this);
    }

    public void reset(Memoable other)
    {
        RIPEMD128Digest d = (RIPEMD128Digest)other;

        copyIn(d);
    }
}
