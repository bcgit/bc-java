package org.bouncycastle.math.ec.rfc8032;

import java.math.BigInteger;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.math.ec.rfc7748.X25519Field;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

public abstract class Ed25519
{
    private static final int POINT_BYTES = 32;
    private static final int SCALAR_INTS = 8;
    private static final int SCALAR_BYTES = SCALAR_INTS * 4;

    public static final int PUBLIC_KEY_SIZE = POINT_BYTES;
    public static final int SECRET_KEY_SIZE = 32;
    public static final int SIGNATURE_SIZE = POINT_BYTES + SCALAR_BYTES;

    private static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger L = BigInteger.ONE.shiftLeft(252).add(new BigInteger("14DEF9DEA2F79CD65812631A5CF5D3ED", 16));

    private static final int[] B_x = new int[]{ 0x0325D51A, 0x018B5823, 0x007B2C95, 0x0304A92D, 0x00D2598E, 0x01D6DC5C,
        0x01388C7F, 0x013FEC0A, 0x029E6B72, 0x0042D26D };    
    private static final int[] B_y = new int[]{ 0x02666658, 0x01999999, 0x00666666, 0x03333333, 0x00CCCCCC, 0x02666666,
        0x01999999, 0x00666666, 0x03333333, 0x00CCCCCC, };
    private static final int[] B_t_d2 = new int[]{ 0x037AAA68, 0x02448161, 0x0049EABC, 0x011E6556, 0x004DB3D0,
        0x0143598C, 0x02DF72F7, 0x005A85A1, 0x0344F863, 0x00DE22F6 };
    private static final int[] C_d = new int[]{ 0x035978A3, 0x02D37284, 0x018AB75E, 0x026A0A0E, 0x0000E014, 0x0379E898,
        0x01D01E5D, 0x01E738CC, 0x03715B7F, 0x00A406D9 };
    private static final int[] C_d2 = new int[]{ 0x02B2F159, 0x01A6E509, 0x01156EBD, 0x00D4141D, 0x0001C029, 0x02F3D130,
        0x03A03CBB, 0x01CE7198, 0x02E2B6FF, 0x00480DB3 };

    private static class PointXYTZ
    {
        int[] x = X25519Field.create();
        int[] y = X25519Field.create();
        int[] t = X25519Field.create();
        int[] z = X25519Field.create();
    }

    private static BigInteger big(byte[] bs)
    {
        return new BigInteger(1, Arrays.reverse(bs));
    }

    private static byte[] calculateS(byte[] r, byte[] k, byte[] s)
    {
        BigInteger S = big(k).multiply(big(s)).add(big(r)).mod(L);

        return Arrays.reverse(BigIntegers.asUnsignedByteArray(SCALAR_BYTES, S));
    }

    private static boolean checkFieldElement(byte[] fe)
    {
        return big(fe).compareTo(P) < 0;
    }

    private static boolean checkScalar(byte[] s)
    {
        return big(s).compareTo(L) < 0;
    }

    private static int decode32(byte[] bs, int off)
    {
        int n = bs[off] & 0xFF;
        n |= (bs[++off] & 0xFF) << 8;
        n |= (bs[++off] & 0xFF) << 16;
        n |=  bs[++off]         << 24;
        return n;
    }

    private static boolean decodePointVar(byte[] p, int pOff, PointXYTZ r)
    {
        byte[] py = Arrays.copyOfRange(p, pOff, pOff + POINT_BYTES);
        int x_0 = (py[POINT_BYTES - 1] & 0x80) >>> 7;
        py[POINT_BYTES - 1] &= 0x7F;

        if (!checkFieldElement(py))
        {
            return false;
        }

        X25519Field.decode(py, 0, r.y);

        int[] u = X25519Field.create();
        int[] v = X25519Field.create();

        X25519Field.sqr(r.y, u);
        X25519Field.mul(C_d, u, v);
        X25519Field.subOne(u);
        X25519Field.addOne(v);

        if (!X25519Field.sqrtRatioVar(u, v, r.x))
        {
            return false;
        }

        X25519Field.normalize(r.x);
        if (x_0 == 1 && X25519Field.isZeroVar(r.x))
        {
            return false;
        }

        if (x_0 != (r.x[0] & 1))
        {
            X25519Field.negate(r.x, r.x);
        }

        pointExtendXY(r);
        return true;
    }

    private static void decodeScalar(byte[] k, int kOff, int[] n)
    {
        for (int i = 0; i < SCALAR_INTS; ++i)
        {
            n[i] = decode32(k, kOff + i * 4);
        }
    }

    private static void dom2(SHA512Digest d)
    {
        
    }

    private static void encodePoint(PointXYTZ p, byte[] r, int rOff)
    {
        int[] x = X25519Field.create();
        int[] y = X25519Field.create();

        X25519Field.inv(p.z, y);
        X25519Field.mul(p.x, y, x);
        X25519Field.mul(p.y, y, y);
        X25519Field.normalize(x);
        X25519Field.normalize(y);

        X25519Field.encode(y, r, rOff);
        r[rOff + POINT_BYTES - 1] |= ((x[0] & 1) << 7);
    }

    public static void generatePublicKey(byte[] sk, int skOff, byte[] pk, int pkOff)
    {
        // TODO Not currently constant-time (see use of ...Var methods)

        Digest d = new SHA512Digest();
        d.update(sk, skOff, SECRET_KEY_SIZE);

        byte[] h = new byte[d.getDigestSize()];
        d.doFinal(h, 0);

        byte[] s = new byte[SCALAR_BYTES];
        pruneScalar(h, 0, s);

        scalarMultBaseEncodedVar(s, pk, pkOff);
    }

    private static void ph(SHA512Digest d, byte[] m, int mOff, int mLen)
    {
        d.update(m, mOff, mLen);
    }

    private static void pointAdd(PointXYTZ p, PointXYTZ r)
    {
        int[] A = X25519Field.create();
        int[] B = X25519Field.create();
        int[] C = X25519Field.create();
        int[] D = X25519Field.create();
        int[] E = X25519Field.create();
        int[] F = X25519Field.create();
        int[] G = X25519Field.create();
        int[] H = X25519Field.create();

        X25519Field.apm(r.y, r.x, B, A);
        X25519Field.apm(p.y, p.x, D, C);
        X25519Field.mul(A, C, A);
        X25519Field.mul(B, D, B);
        X25519Field.mul(r.t, p.t, C);
        X25519Field.mul(C, C_d2, C);
        X25519Field.mul(r.z, p.z, D);
        X25519Field.add(D, D, D);
        X25519Field.apm(B, A, H, E);
        X25519Field.apm(D, C, G, F);
        X25519Field.carry(G);
        X25519Field.mul(E, F, r.x);
        X25519Field.mul(G, H, r.y);
        X25519Field.mul(E, H, r.t);
        X25519Field.mul(F, G, r.z);
    }

    private static void pointAddBase(PointXYTZ r)
    {
        int[] A = X25519Field.create();
        int[] B = X25519Field.create();
        int[] C = X25519Field.create();
        int[] D = X25519Field.create();
        int[] E = X25519Field.create();
        int[] F = X25519Field.create();
        int[] G = X25519Field.create();
        int[] H = X25519Field.create();

        X25519Field.apm(r.y, r.x, B, A);
        X25519Field.apm(B_y, B_x, D, C);
        X25519Field.mul(A, C, A);
        X25519Field.mul(B, D, B);
        X25519Field.mul(r.t, B_t_d2, C);
        X25519Field.add(r.z, r.z, D);
        X25519Field.apm(B, A, H, E);
        X25519Field.apm(D, C, G, F);
        X25519Field.carry(G);
        X25519Field.mul(E, F, r.x);
        X25519Field.mul(G, H, r.y);
        X25519Field.mul(E, H, r.t);
        X25519Field.mul(F, G, r.z);
    }

    private static void pointDouble(PointXYTZ r)
    {
        int[] A = X25519Field.create();
        int[] B = X25519Field.create();
        int[] C = X25519Field.create();
        int[] E = X25519Field.create();
        int[] F = X25519Field.create();
        int[] G = X25519Field.create();
        int[] H = X25519Field.create();

        X25519Field.sqr(r.x, A);
        X25519Field.sqr(r.y, B);
        X25519Field.sqr(r.z, C);
        X25519Field.add(C, C, C);
        X25519Field.apm(A, B, H, G);
        X25519Field.add(r.x, r.y, E);
        X25519Field.sqr(E, E);
        X25519Field.sub(H, E, E);
        X25519Field.add(C, G, F);
        X25519Field.carry(F);
        X25519Field.mul(E, F, r.x);
        X25519Field.mul(G, H, r.y);
        X25519Field.mul(E, H, r.t);
        X25519Field.mul(F, G, r.z);
    }

    private static void pointExtendXY(PointXYTZ p)
    {
        X25519Field.mul(p.x, p.y, p.t);
        X25519Field.one(p.z);
    }

    public static void precompute()
    {
    }

    private static void pruneScalar(byte[] n, int nOff, byte[] r)
    {
        System.arraycopy(n,  nOff, r, 0, SCALAR_BYTES);

        r[0] &= 0xF8;
        r[SCALAR_BYTES - 1] &= 0x7F;
        r[SCALAR_BYTES - 1] |= 0x40;
    }

    private static byte[] reduceScalarVar(byte[] n)
    {
        return Arrays.reverse(BigIntegers.asUnsignedByteArray(SCALAR_BYTES, big(n).mod(L)));
    }

    private static void scalarMultVar(int[] n, PointXYTZ p, PointXYTZ r)
    {
        X25519Field.zero(r.x);
        X25519Field.one(r.y);
        X25519Field.zero(r.t);
        X25519Field.one(r.z);

        for (int bit = 255; bit >= 0; --bit)
        {
            int word = bit >>> 5, shift = bit & 0x1F;
            int kt = (n[word] >>> shift) & 1;

            pointDouble(r);

            if (kt != 0)
            {
                pointAdd(p, r);
            }
        }
    }

    private static void scalarMultBaseVar(int[] n, PointXYTZ r)
    {
        X25519Field.zero(r.x);
        X25519Field.one(r.y);
        X25519Field.zero(r.t);
        X25519Field.one(r.z);

        for (int bit = 255; bit >= 0; --bit)
        {
            int word = bit >>> 5, shift = bit & 0x1F;
            int kt = (n[word] >>> shift) & 1;

            pointDouble(r);

            if (kt != 0)
            {
                pointAddBase(r);
            }
        }
    }

    private static void scalarMultBaseEncodedVar(byte[] k, byte[] r, int rOff)
    {
        int[] n = new int[SCALAR_INTS];
        decodeScalar(k, 0, n);

        PointXYTZ p = new PointXYTZ();
        scalarMultBaseVar(n, p);

        encodePoint(p, r, rOff);
    }

    public static void sign(byte[] sk, int skOff, byte[] m, int mOff, int mLen, byte[] sig, int sigOff)
    {
        // TODO Not currently constant-time (see use of ...Var methods)

        SHA512Digest d = new SHA512Digest();
        byte[] h = new byte[d.getDigestSize()];

        d.update(sk, skOff, SECRET_KEY_SIZE);
        d.doFinal(h, 0);

        byte[] s = new byte[SCALAR_BYTES];
        pruneScalar(h, 0, s);

        byte[] A = new byte[POINT_BYTES];
        scalarMultBaseEncodedVar(s, A, 0);

        dom2(d);
        d.update(h, 32, 32);
        ph(d, m, mOff, mLen);
        d.doFinal(h,  0);

        byte[] r = reduceScalarVar(h);
        byte[] R = new byte[POINT_BYTES];
        scalarMultBaseEncodedVar(r, R, 0);

        dom2(d);
        d.update(R, 0, POINT_BYTES);
        d.update(A, 0, POINT_BYTES);
        ph(d, m, mOff, mLen);
        d.doFinal(h,  0);

        byte[] k = reduceScalarVar(h);
        byte[] S = calculateS(r, k, s);

        System.arraycopy(R, 0, sig, sigOff, POINT_BYTES);
        System.arraycopy(S, 0, sig, sigOff + POINT_BYTES, SCALAR_BYTES);
    }

    public static void sign(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] m, int mOff, int mLen, byte[] sig, int sigOff)
    {
        // TODO Not currently constant-time (see use of ...Var methods)

        SHA512Digest d = new SHA512Digest();
        byte[] h = new byte[d.getDigestSize()];

        d.update(sk, skOff, SECRET_KEY_SIZE);
        d.doFinal(h, 0);

        byte[] s = new byte[SCALAR_BYTES];
        pruneScalar(h, 0, s);

        dom2(d);
        d.update(h, 32, 32);
        ph(d, m, mOff, mLen);
        d.doFinal(h,  0);

        byte[] r = reduceScalarVar(h);
        byte[] R = new byte[POINT_BYTES];
        scalarMultBaseEncodedVar(r, R, 0);

        dom2(d);
        d.update(R, 0, POINT_BYTES);
        d.update(pk, pkOff, POINT_BYTES);
        ph(d, m, mOff, mLen);
        d.doFinal(h,  0);

        byte[] k = reduceScalarVar(h);
        byte[] S = calculateS(r, k, s);

        System.arraycopy(R, 0, sig, sigOff, POINT_BYTES);
        System.arraycopy(S, 0, sig, sigOff + POINT_BYTES, SCALAR_BYTES);
    }

    public static boolean verify(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] m, int mOff, int mLen)
    {
        // TODO Not currently constant-time (see use of ...Var methods)

        PointXYTZ pA = new PointXYTZ();
        if (!decodePointVar(pk, pkOff, pA))
        {
            return false;
        }

        byte[] R = Arrays.copyOfRange(sig, sigOff, sigOff + POINT_BYTES);
        byte[] S = Arrays.copyOfRange(sig, sigOff + POINT_BYTES, sigOff + SIGNATURE_SIZE);

        if (!checkScalar(S))
        {
            return false;
        }

        PointXYTZ pR = new PointXYTZ();
        if (!decodePointVar(R, 0, pR))
        {
            return false;
        }

        SHA512Digest d = new SHA512Digest();
        byte[] h = new byte[d.getDigestSize()];

        dom2(d);
        d.update(R, 0, POINT_BYTES);
        d.update(pk, pkOff, POINT_BYTES);
        ph(d, m, mOff, mLen);
        d.doFinal(h,  0);

        byte[] k = reduceScalarVar(h);

        byte[] lhs = new byte[POINT_BYTES];
        scalarMultBaseEncodedVar(S, lhs, 0);

        byte[] rhs = new byte[POINT_BYTES];
        int[] n = new int[SCALAR_INTS];
        PointXYTZ p = new PointXYTZ();
        decodeScalar(k, 0, n);
        scalarMultVar(n, pA, p);
        pointAdd(pR, p);
        encodePoint(p, rhs, 0);

        return Arrays.areEqual(lhs, rhs);
    }
}
