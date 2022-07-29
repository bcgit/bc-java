package org.bouncycastle.crypto.digests;


import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/**
 * implementation of MD4 as RFC 1320 by R. Rivest, MIT Laboratory for
 * Computer Science and RSA Data Security, Inc.
 * <p>
 * <b>NOTE</b>: This algorithm is only included for backwards compatability
 * with legacy applications, it's not secure, don't use it for anything new!
 */
public class MD4Digest
    extends GeneralDigest
{
    private static final int    DIGEST_LENGTH = 16;

    private int     H1, H2, H3, H4;         // IV's

    private int[]   X = new int[16];
    private int     xOff;

    public MD4Digest()
    {
        this(CryptoServicePurpose.ANY);
    }

    public MD4Digest(CryptoServicePurpose purpose)
    {
        super(purpose);

        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, DIGEST_LENGTH * 4, purpose));

        reset();
    }

    public MD4Digest(MD4Digest t)
    {
        super(t.purpose);

        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, DIGEST_LENGTH * 4, purpose));

        copyIn(t);
    }

    private void copyIn(MD4Digest t)
    {
        super.copyIn(t);

        H1 = t.H1;
        H2 = t.H2;
        H3 = t.H3;
        H4 = t.H4;

        System.arraycopy(t.X, 0, X, 0, t.X.length);
        xOff = t.xOff;
    }

    public String getAlgorithmName()
    {
        return "MD4";
    }

    public int getDigestSize()
    {
        return DIGEST_LENGTH;
    }

    protected void processWord(byte[] in, int inOff)
    {
        X[xOff++] = Pack.littleEndianToInt(in, inOff);

        if (xOff == 16)
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

        X[14] = (int)(bitLength & 0xffffffff);
        X[15] = (int)(bitLength >>> 32);
    }

    public int doFinal(byte[] out, int outOff)
    {
        finish();

        Pack.intToLittleEndian(H1, out, outOff);
        Pack.intToLittleEndian(H2, out, outOff + 4);
        Pack.intToLittleEndian(H3, out, outOff + 8);
        Pack.intToLittleEndian(H4, out, outOff + 12);

        reset();

        return DIGEST_LENGTH;
    }

    /**
     * reset the chaining variables to the IV values.
     */
    public void reset()
    {
        super.reset();

        H1 = 0x67452301;
        H2 = 0xefcdab89;
        H3 = 0x98badcfe;
        H4 = 0x10325476;

        xOff = 0;

        for (int i = 0; i != X.length; i++)
        {
            X[i] = 0;
        }
    }

    //
    // round 1 left rotates
    //
    private static final int S11 = 3;
    private static final int S12 = 7;
    private static final int S13 = 11;
    private static final int S14 = 19;

    //
    // round 2 left rotates
    //
    private static final int S21 = 3;
    private static final int S22 = 5;
    private static final int S23 = 9;
    private static final int S24 = 13;

    //
    // round 3 left rotates
    //
    private static final int S31 = 3;
    private static final int S32 = 9;
    private static final int S33 = 11;
    private static final int S34 = 15;

    /*
     * rotate int x left n bits.
     */
    private int rotateLeft(
        int x,
        int n)
    {
        return (x << n) | (x >>> (32 - n));
    }

    /*
     * F, G, H and I are the basic MD4 functions.
     */
    private int F(
        int u,
        int v,
        int w)
    {
        return (u & v) | (~u & w);
    }

    private int G(
        int u,
        int v,
        int w)
    {
        return (u & v) | (u & w) | (v & w);
    }

    private int H(
        int u,
        int v,
        int w)
    {
        return u ^ v ^ w;
    }

    protected void processBlock()
    {
        int a = H1;
        int b = H2;
        int c = H3;
        int d = H4;

        //
        // Round 1 - F cycle, 16 times.
        //
        a = rotateLeft(a + F(b, c, d) + X[ 0], S11);
        d = rotateLeft(d + F(a, b, c) + X[ 1], S12);
        c = rotateLeft(c + F(d, a, b) + X[ 2], S13);
        b = rotateLeft(b + F(c, d, a) + X[ 3], S14);
        a = rotateLeft(a + F(b, c, d) + X[ 4], S11);
        d = rotateLeft(d + F(a, b, c) + X[ 5], S12);
        c = rotateLeft(c + F(d, a, b) + X[ 6], S13);
        b = rotateLeft(b + F(c, d, a) + X[ 7], S14);
        a = rotateLeft(a + F(b, c, d) + X[ 8], S11);
        d = rotateLeft(d + F(a, b, c) + X[ 9], S12);
        c = rotateLeft(c + F(d, a, b) + X[10], S13);
        b = rotateLeft(b + F(c, d, a) + X[11], S14);
        a = rotateLeft(a + F(b, c, d) + X[12], S11);
        d = rotateLeft(d + F(a, b, c) + X[13], S12);
        c = rotateLeft(c + F(d, a, b) + X[14], S13);
        b = rotateLeft(b + F(c, d, a) + X[15], S14);

        //
        // Round 2 - G cycle, 16 times.
        //
        a = rotateLeft(a + G(b, c, d) + X[ 0] + 0x5a827999, S21);
        d = rotateLeft(d + G(a, b, c) + X[ 4] + 0x5a827999, S22);
        c = rotateLeft(c + G(d, a, b) + X[ 8] + 0x5a827999, S23);
        b = rotateLeft(b + G(c, d, a) + X[12] + 0x5a827999, S24);
        a = rotateLeft(a + G(b, c, d) + X[ 1] + 0x5a827999, S21);
        d = rotateLeft(d + G(a, b, c) + X[ 5] + 0x5a827999, S22);
        c = rotateLeft(c + G(d, a, b) + X[ 9] + 0x5a827999, S23);
        b = rotateLeft(b + G(c, d, a) + X[13] + 0x5a827999, S24);
        a = rotateLeft(a + G(b, c, d) + X[ 2] + 0x5a827999, S21);
        d = rotateLeft(d + G(a, b, c) + X[ 6] + 0x5a827999, S22);
        c = rotateLeft(c + G(d, a, b) + X[10] + 0x5a827999, S23);
        b = rotateLeft(b + G(c, d, a) + X[14] + 0x5a827999, S24);
        a = rotateLeft(a + G(b, c, d) + X[ 3] + 0x5a827999, S21);
        d = rotateLeft(d + G(a, b, c) + X[ 7] + 0x5a827999, S22);
        c = rotateLeft(c + G(d, a, b) + X[11] + 0x5a827999, S23);
        b = rotateLeft(b + G(c, d, a) + X[15] + 0x5a827999, S24);

        //
        // Round 3 - H cycle, 16 times.
        //
        a = rotateLeft(a + H(b, c, d) + X[ 0] + 0x6ed9eba1, S31);
        d = rotateLeft(d + H(a, b, c) + X[ 8] + 0x6ed9eba1, S32);
        c = rotateLeft(c + H(d, a, b) + X[ 4] + 0x6ed9eba1, S33);
        b = rotateLeft(b + H(c, d, a) + X[12] + 0x6ed9eba1, S34);
        a = rotateLeft(a + H(b, c, d) + X[ 2] + 0x6ed9eba1, S31);
        d = rotateLeft(d + H(a, b, c) + X[10] + 0x6ed9eba1, S32);
        c = rotateLeft(c + H(d, a, b) + X[ 6] + 0x6ed9eba1, S33);
        b = rotateLeft(b + H(c, d, a) + X[14] + 0x6ed9eba1, S34);
        a = rotateLeft(a + H(b, c, d) + X[ 1] + 0x6ed9eba1, S31);
        d = rotateLeft(d + H(a, b, c) + X[ 9] + 0x6ed9eba1, S32);
        c = rotateLeft(c + H(d, a, b) + X[ 5] + 0x6ed9eba1, S33);
        b = rotateLeft(b + H(c, d, a) + X[13] + 0x6ed9eba1, S34);
        a = rotateLeft(a + H(b, c, d) + X[ 3] + 0x6ed9eba1, S31);
        d = rotateLeft(d + H(a, b, c) + X[11] + 0x6ed9eba1, S32);
        c = rotateLeft(c + H(d, a, b) + X[ 7] + 0x6ed9eba1, S33);
        b = rotateLeft(b + H(c, d, a) + X[15] + 0x6ed9eba1, S34);

        H1 += a;
        H2 += b;
        H3 += c;
        H4 += d;

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
        return new MD4Digest(this);
    }

    public void reset(Memoable other)
    {
        MD4Digest d = (MD4Digest)other;

        copyIn(d);
    }

    protected CryptoServiceProperties cryptoServiceProperties()
    {
        return Utils.getDefaultProperties(this, purpose);
    }
}
