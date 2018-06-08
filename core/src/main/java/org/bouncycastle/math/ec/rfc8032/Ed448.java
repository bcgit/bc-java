package org.bouncycastle.math.ec.rfc8032;

import java.math.BigInteger;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.math.ec.rfc7748.X448Field;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;

public abstract class Ed448
{
    private static final int POINT_BYTES = 57;
    private static final int SCALAR_INTS = 14;
    private static final int SCALAR_BYTES = SCALAR_INTS * 4 + 1;

    public static final int PUBLIC_KEY_SIZE = POINT_BYTES;
    public static final int SECRET_KEY_SIZE = 57;
    public static final int SIGNATURE_SIZE = POINT_BYTES + SCALAR_BYTES;

    private static final byte[] DOM4_PREFIX = Strings.toByteArray("SigEd448");

    private static final BigInteger P = BigInteger.ONE.shiftLeft(448).subtract(BigInteger.ONE.shiftLeft(224)).subtract(BigInteger.ONE);
    private static final BigInteger L = BigInteger.ONE.shiftLeft(446).subtract(
        new BigInteger("8335DC163BB124B65129C96FDE933D8D723A70AADC873D6D54A7BB0D", 16));

    private static final int[] B_x = new int[] { 0x070CC05E, 0x026A82BC, 0x00938E26, 0x080E18B0, 0x0511433B, 0x0F72AB66, 0x0412AE1A,
        0x0A3D3A46, 0x0A6DE324, 0x00F1767E, 0x04657047, 0x036DA9E1, 0x05A622BF, 0x0ED221D1, 0x066BED0D, 0x04F1970C };
    private static final int[] B_y = new int[] { 0x0230FA14, 0x008795BF, 0x07C8AD98, 0x0132C4ED, 0x09C4FDBD, 0x01CE67C3, 0x073AD3FF,
        0x005A0C2D, 0x07789C1E, 0x0A398408, 0x0A73736C, 0x0C7624BE, 0x003756C9, 0x02488762, 0x016EB6BC, 0x0693F467 };
    private static final int C_d = -39081;

    private static class PointXYZ
    {
        int[] x = X448Field.create();
        int[] y = X448Field.create();
        int[] z = X448Field.create();
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

    private static boolean checkContext(byte[] ctx)
    {
        return ctx != null && ctx.length < 256;
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

    private static boolean decodePointVar(byte[] p, int pOff, PointXYZ r)
    {
        byte[] py = Arrays.copyOfRange(p, pOff, pOff + POINT_BYTES);
        int x_0 = (py[POINT_BYTES - 1] & 0x80) >>> 7;
        py[POINT_BYTES - 1] &= 0x7F;

        if (!checkFieldElement(py))
        {
            return false;
        }

        X448Field.decode(py, 0, r.y);

        int[] one = X448Field.create();
        X448Field.one(one);

        int[] u = X448Field.create();
        int[] v = X448Field.create();

        X448Field.sqr(r.y, u);
        X448Field.mul(u, -C_d, v);
        
        X448Field.negate(u, u);
        X448Field.addOne(u);
        X448Field.addOne(v);

        if (!X448Field.sqrtRatioVar(u, v, r.x))
        {
            return false;
        }

        X448Field.normalize(r.x);
        if (x_0 == 1 && X448Field.isZeroVar(r.x))
        {
            return false;
        }

        if (x_0 != (r.x[0] & 1))
        {
            X448Field.negate(r.x, r.x);
        }

        pointExtendXY(r);
        return true;
    }

    private static void decodeScalar(byte[] k, int kOff, int[] n)
    {
//        assert k[kOff + SCALAR_BYTES - 1] == 0x00;

        for (int i = 0; i < SCALAR_INTS; ++i)
        {
            n[i] = decode32(k, kOff + i * 4);
        }
    }

    private static void dom4(SHAKEDigest d, byte x, byte[] y)
    {
        d.update(DOM4_PREFIX, 0, DOM4_PREFIX.length);
        d.update(x);
        d.update((byte)y.length);
        d.update(y, 0, y.length);
    }

    private static void encodePoint(PointXYZ p, byte[] r, int rOff)
    {
        int[] x = X448Field.create();
        int[] y = X448Field.create();

        X448Field.inv(p.z, y);
        X448Field.mul(p.x, y, x);
        X448Field.mul(p.y, y, y);
        X448Field.normalize(x);
        X448Field.normalize(y);

        X448Field.encode(y, r, rOff);
        r[rOff + POINT_BYTES - 1] = (byte)((x[0] & 1) << 7);
    }

    public static void generatePublicKey(byte[] sk, int skOff, byte[] pk, int pkOff)
    {
        // TODO Not currently constant-time (see use of ...Var methods)

        SHAKEDigest d = new SHAKEDigest(256);
        byte[] h = new byte[SCALAR_BYTES * 2];

        d.update(sk, skOff, SECRET_KEY_SIZE);
        d.doFinal(h, 0, h.length);

        byte[] s = new byte[SCALAR_BYTES];
        pruneScalar(h, 0, s);

        scalarMultBaseEncodedVar(s, pk, pkOff);
    }

    private static void pointAdd(PointXYZ p, PointXYZ r)
    {
        int[] A = X448Field.create();
        int[] B = X448Field.create();
        int[] C = X448Field.create();
        int[] D = X448Field.create();
        int[] E = X448Field.create();
        int[] F = X448Field.create();
        int[] G = X448Field.create();
        int[] H = X448Field.create();

        X448Field.mul(p.z, r.z, A);
        X448Field.sqr(A, B);
        X448Field.mul(p.x, r.x, C);
        X448Field.mul(p.y, r.y, D);
        X448Field.mul(C, D, E);
        X448Field.mul(E, -C_d, E);
//        X448Field.apm(B, E, F, G);
        X448Field.add(B, E, F);
        X448Field.sub(B, E, G);
        X448Field.add(p.x, p.y, B);
        X448Field.add(r.x, r.y, E);
        X448Field.mul(B, E, H);
//        X448Field.apm(D, C, B, E);
        X448Field.add(D, C, B);
        X448Field.sub(D, C, E);
        X448Field.carry(B);
        X448Field.sub(H, B, H);
        X448Field.mul(H, A, H);
        X448Field.mul(E, A, E);
        X448Field.mul(F, H, r.x);
        X448Field.mul(E, G, r.y);
        X448Field.mul(F, G, r.z);
    }

    private static void pointAddBase(PointXYZ r)
    {
        int[] B = X448Field.create();
        int[] C = X448Field.create();
        int[] D = X448Field.create();
        int[] E = X448Field.create();
        int[] F = X448Field.create();
        int[] G = X448Field.create();
        int[] H = X448Field.create();

        X448Field.sqr(r.z, B);
        X448Field.mul(B_x, r.x, C);
        X448Field.mul(B_y, r.y, D);
        X448Field.mul(C, D, E);
        X448Field.mul(E, -C_d, E);
//        X448Field.apm(B, E, F, G);
        X448Field.add(B, E, F);
        X448Field.sub(B, E, G);
        X448Field.add(B_x, B_y, B);
        X448Field.add(r.x, r.y, E);
        X448Field.mul(B, E, H);
//        X448Field.apm(D, C, B, E);
        X448Field.add(D, C, B);
        X448Field.sub(D, C, E);
        X448Field.carry(B);
        X448Field.sub(H, B, H);
        X448Field.mul(H, r.z, H);
        X448Field.mul(E, r.z, E);
        X448Field.mul(F, H, r.x);
        X448Field.mul(E, G, r.y);
        X448Field.mul(F, G, r.z);
    }

    private static void pointDouble(PointXYZ r)
    {
        int[] B = X448Field.create();
        int[] C = X448Field.create();
        int[] D = X448Field.create();
        int[] E = X448Field.create();
        int[] H = X448Field.create();
        int[] J = X448Field.create();

        X448Field.add(r.x, r.y, B);
        X448Field.sqr(B, B);
        X448Field.sqr(r.x, C);
        X448Field.sqr(r.y, D);
        X448Field.add(C, D, E);
        X448Field.carry(E);
        X448Field.sqr(r.z, H);
        X448Field.add(H, H, H);
        X448Field.carry(H);
        X448Field.sub(E, H, J);
        X448Field.sub(B, E, B);
        X448Field.sub(C, D, C);
        X448Field.mul(B, J, r.x);
        X448Field.mul(E, C, r.y);
        X448Field.mul(E, J, r.z);
    }

    private static void pointExtendXY(PointXYZ p)
    {
        X448Field.one(p.z);
    }

    public static void precompute()
    {
    }

    private static void pruneScalar(byte[] n, int nOff, byte[] r)
    {
        System.arraycopy(n, nOff, r, 0, SCALAR_BYTES);

        r[0] &= 0xFC;
        r[SCALAR_BYTES - 1] &= 0x00;
        r[SCALAR_BYTES - 2] |= 0x80;
    }

    private static byte[] reduceScalarVar(byte[] n)
    {
        return Arrays.reverse(BigIntegers.asUnsignedByteArray(SCALAR_BYTES, big(n).mod(L)));
    }

    private static void scalarMultVar(int[] n, PointXYZ p, PointXYZ r)
    {
        X448Field.zero(r.x);
        X448Field.one(r.y);
        X448Field.one(r.z);

        for (int bit = 447; bit >= 0; --bit)
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

    private static void scalarMultBaseVar(int[] n, PointXYZ r)
    {
        X448Field.zero(r.x);
        X448Field.one(r.y);
        X448Field.one(r.z);

        for (int bit = 447; bit >= 0; --bit)
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

        PointXYZ p = new PointXYZ();
        scalarMultBaseVar(n, p);

        encodePoint(p, r, rOff);
    }

    public static void sign(byte[] sk, int skOff, byte[] ctx, byte[] m, int mOff, int mLen, byte[] sig, int sigOff)
    {
        // TODO Not currently constant-time (see use of ...Var methods)

        if (!checkContext(ctx))
        {
            throw new IllegalArgumentException("ctx");
        }

        byte phflag = 0x00;

        SHAKEDigest d = new SHAKEDigest(256);
        byte[] h = new byte[SCALAR_BYTES * 2];

//        dom4(d, phflag, ctx);
        d.update(sk, skOff, SECRET_KEY_SIZE);
        d.doFinal(h, 0, h.length);

        byte[] s = new byte[SCALAR_BYTES];
        pruneScalar(h, 0, s);

        byte[] pk = new byte[POINT_BYTES];
        scalarMultBaseEncodedVar(s, pk, 0);

        dom4(d, phflag, ctx);
        d.update(h, SCALAR_BYTES, SCALAR_BYTES);
        d.update(m, mOff, mLen);
        d.doFinal(h, 0, h.length);

        byte[] r = reduceScalarVar(h);
        byte[] R = new byte[POINT_BYTES];
        scalarMultBaseEncodedVar(r, R, 0);

        dom4(d, phflag, ctx);
        d.update(R, 0, POINT_BYTES);
        d.update(pk, 0, POINT_BYTES);
        d.update(m, mOff, mLen);
        d.doFinal(h, 0, h.length);

        byte[] k = reduceScalarVar(h);
        byte[] S = calculateS(r, k, s);

        System.arraycopy(R, 0, sig, sigOff, POINT_BYTES);
        System.arraycopy(S, 0, sig, sigOff + POINT_BYTES, SCALAR_BYTES);
    }

    public static void sign(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] ctx, byte[] m, int mOff, int mLen, byte[] sig, int sigOff)
    {
        // TODO Not currently constant-time (see use of ...Var methods)

        if (!checkContext(ctx))
        {
            throw new IllegalArgumentException("ctx");
        }

        byte phflag = 0x00;

        SHAKEDigest d = new SHAKEDigest(256);
        byte[] h = new byte[SCALAR_BYTES * 2];

//        dom4(d, phflag, ctx);
        d.update(sk, skOff, SECRET_KEY_SIZE);
        d.doFinal(h, 0, h.length);

        byte[] s = new byte[SCALAR_BYTES];
        pruneScalar(h, 0, s);

        dom4(d, phflag, ctx);
        d.update(h, SCALAR_BYTES, SCALAR_BYTES);
        d.update(m, mOff, mLen);
        d.doFinal(h, 0, h.length);

        byte[] r = reduceScalarVar(h);
        byte[] R = new byte[POINT_BYTES];
        scalarMultBaseEncodedVar(r, R, 0);

        dom4(d, phflag, ctx);
        d.update(R, 0, POINT_BYTES);
        d.update(pk, pkOff, POINT_BYTES);
        d.update(m, mOff, mLen);
        d.doFinal(h, 0, h.length);

        byte[] k = reduceScalarVar(h);
        byte[] S = calculateS(r, k, s);

        System.arraycopy(R, 0, sig, sigOff, POINT_BYTES);
        System.arraycopy(S, 0, sig, sigOff + POINT_BYTES, SCALAR_BYTES);
    }

    public static boolean verify(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] ctx, byte[] m, int mOff, int mLen)
    {
        // TODO Not currently constant-time (see use of ...Var methods)

        if (!checkContext(ctx))
        {
            throw new IllegalArgumentException("ctx");
        }

        PointXYZ pA = new PointXYZ();
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

        PointXYZ pR = new PointXYZ();
        if (!decodePointVar(R, 0, pR))
        {
            return false;
        }

        byte phflag = 0x00;

        SHAKEDigest d = new SHAKEDigest(256);
        byte[] h = new byte[SCALAR_BYTES * 2];

        dom4(d, phflag, ctx);
        d.update(R, 0, POINT_BYTES);
        d.update(pk, pkOff, POINT_BYTES);
        d.update(m, mOff, mLen);
        d.doFinal(h, 0, h.length);

        byte[] k = reduceScalarVar(h);

        byte[] lhs = new byte[POINT_BYTES];
        scalarMultBaseEncodedVar(S, lhs, 0);

        byte[] rhs = new byte[POINT_BYTES];
        int[] n = new int[SCALAR_INTS];
        PointXYZ p = new PointXYZ();
        decodeScalar(k, 0, n);
        scalarMultVar(n, pA, p);
        pointAdd(pR, p);
        encodePoint(p, rhs, 0);

        return Arrays.areEqual(lhs, rhs);
    }
}
