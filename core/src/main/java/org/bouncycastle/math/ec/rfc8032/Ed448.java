package org.bouncycastle.math.ec.rfc8032;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.math.ec.rfc7748.X448;
import org.bouncycastle.math.ec.rfc7748.X448Field;
import org.bouncycastle.math.raw.Nat;

/**
 * A low-level implementation of the Ed448 and Ed448ph instantiations of the Edwards-Curve Digital Signature
 * Algorithm specified in <a href="https://www.rfc-editor.org/rfc/rfc8032">RFC 8032</a>.
 * <p>
 * The implementation uses the "signed mult-comb" algorithm (for scalar multiplication by a fixed point) from
 * <a href="https://ia.cr/2012/309">Mike Hamburg, "Fast and compact elliptic-curve cryptography"</a>. Standard
 * <a href="https://hyperelliptic.org/EFD/g1p/auto-edwards-projective.html">projective coordinates</a> are
 * used for most point arithmetic.
 */
public abstract class Ed448
{
    // x^2 + y^2 == 1 - 39081 * x^2 * y^2

    public static final class Algorithm
    {
        public static final int Ed448 = 0;
        public static final int Ed448ph = 1;
    }

    public static final class PublicPoint
    {
        final int[] data;

        PublicPoint(int[] data)
        {
            this.data = data;
        }
    }

    private static class F extends X448Field {};

    private static final int COORD_INTS = 14;
    private static final int POINT_BYTES = COORD_INTS * 4 + 1;
    private static final int SCALAR_INTS = 14;
    private static final int SCALAR_BYTES = SCALAR_INTS * 4 + 1;

    public static final int PREHASH_SIZE = 64;
    public static final int PUBLIC_KEY_SIZE = POINT_BYTES;
    public static final int SECRET_KEY_SIZE = 57;
    public static final int SIGNATURE_SIZE = POINT_BYTES + SCALAR_BYTES;

    // "SigEd448"
    private static final byte[] DOM4_PREFIX = new byte[]{ 0x53, 0x69, 0x67, 0x45, 0x64, 0x34, 0x34, 0x38 };

    private static final int[] P = new int[] { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };

    private static final int[] B_x = new int[]{ 0x070CC05E, 0x026A82BC, 0x00938E26, 0x080E18B0, 0x0511433B, 0x0F72AB66,
        0x0412AE1A, 0x0A3D3A46, 0x0A6DE324, 0x00F1767E, 0x04657047, 0x036DA9E1, 0x05A622BF, 0x0ED221D1, 0x066BED0D,
        0x04F1970C };
    private static final int[] B_y = new int[]{ 0x0230FA14, 0x008795BF, 0x07C8AD98, 0x0132C4ED, 0x09C4FDBD, 0x01CE67C3,
        0x073AD3FF, 0x005A0C2D, 0x07789C1E, 0x0A398408, 0x0A73736C, 0x0C7624BE, 0x003756C9, 0x02488762, 0x016EB6BC,
        0x0693F467 };

    // 2^225 * B
    private static final int[] B225_x = new int[]{ 0x06909EE2, 0x01D7605C, 0x0995EC8A, 0x0FC4D970, 0x0CF2B361,
        0x02D82E9D, 0x01225F55, 0x007F0EF6, 0x0AEE9C55, 0x0A240C13, 0x05627B54, 0x0D449D1E, 0x03A44575, 0x007164A7,
        0x0BD4BD71, 0x061A15FD };
    private static final int[] B225_y = new int[]{ 0x0D3A9FE4, 0x030696B9, 0x07E7E326, 0x068308C7, 0x0CE0B8C8,
        0x03AC222B, 0x0304DB8E, 0x083EE319, 0x05E5DB0B, 0x0ECA503B, 0x0B1C6539, 0x078A8DCE, 0x02D256BC, 0x04A8B05E,
        0x0BD9FD57, 0x0A1C3CB8 };

    private static final int C_d = -39081;

//    private static final int WNAF_WIDTH = 6;
    private static final int WNAF_WIDTH_225 = 5;
    private static final int WNAF_WIDTH_BASE = 7;

    // scalarMultBase supports varying blocks, teeth, spacing so long as their product is in range [449, 479]
    private static final int PRECOMP_BLOCKS = 5;
    private static final int PRECOMP_TEETH = 5;
    private static final int PRECOMP_SPACING = 18;
    private static final int PRECOMP_RANGE = PRECOMP_BLOCKS * PRECOMP_TEETH * PRECOMP_SPACING; // 448 < range < 480
    private static final int PRECOMP_POINTS = 1 << (PRECOMP_TEETH - 1);
    private static final int PRECOMP_MASK = PRECOMP_POINTS - 1;

    private static final Object PRECOMP_LOCK = new Object();
    private static PointAffine[] PRECOMP_BASE_WNAF = null;
    private static PointAffine[] PRECOMP_BASE225_WNAF = null;
    private static int[] PRECOMP_BASE_COMB = null;

    private static class PointAffine
    {
        int[] x = F.create();
        int[] y = F.create();
    }

    private static class PointProjective
    {
        int[] x = F.create();
        int[] y = F.create();
        int[] z = F.create();
    }

    // Temp space to avoid allocations in point formulae.
    private static class PointTemp
    {
        int[] r0 = F.create();
        int[] r1 = F.create();;
        int[] r2 = F.create();
        int[] r3 = F.create();;
        int[] r4 = F.create();
        int[] r5 = F.create();;
        int[] r6 = F.create();
        int[] r7 = F.create();;
    }

    private static byte[] calculateS(byte[] r, byte[] k, byte[] s)
    {
        int[] t = new int[SCALAR_INTS * 2];     Scalar448.decode(r, t);
        int[] u = new int[SCALAR_INTS];         Scalar448.decode(k, u);
        int[] v = new int[SCALAR_INTS];         Scalar448.decode(s, v);

        Nat.mulAddTo(SCALAR_INTS, u, v, t);

        byte[] result = new byte[SCALAR_BYTES * 2];
        Codec.encode32(t, 0, t.length, result, 0);
        return Scalar448.reduce912(result);
    }

    private static boolean checkContextVar(byte[] ctx)
    {
        return ctx != null && ctx.length < 256;
    }

    private static int checkPoint(PointAffine p)
    {
        int[] t = F.create();
        int[] u = F.create();
        int[] v = F.create();

        F.sqr(p.x, u);
        F.sqr(p.y, v);
        F.mul(u, v, t);
        F.add(u, v, u);
        F.mul(t, -C_d, t);
        F.subOne(t);
        F.add(t, u, t);
        F.normalize(t);

        return F.isZero(t);
    }

    private static int checkPoint(PointProjective p)
    {
        int[] t = F.create();
        int[] u = F.create();
        int[] v = F.create();
        int[] w = F.create();

        F.sqr(p.x, u);
        F.sqr(p.y, v);
        F.sqr(p.z, w);
        F.mul(u, v, t);
        F.add(u, v, u);
        F.mul(u, w, u);
        F.sqr(w, w);
        F.mul(t, -C_d, t);
        F.sub(t, w, t);
        F.add(t, u, t);
        F.normalize(t);

        return F.isZero(t);
    }

    private static boolean checkPointFullVar(byte[] p)
    {
        if ((p[POINT_BYTES - 1] & 0x7F) != 0x00)
            return false;

        int y13 = Codec.decode32(p, 52);

        int t0 = y13;
        int t1 = y13 ^ P[13];

        for (int i = COORD_INTS - 2; i > 0; --i)
        {
            int yi = Codec.decode32(p, i * 4);

            // Reject non-canonical encodings (i.e. >= P)
            if (t1 == 0 && (yi + Integer.MIN_VALUE) > (P[i] + Integer.MIN_VALUE))
                return false;

            t0 |= yi;
            t1 |= yi ^ P[i];
        }

        int y0 = Codec.decode32(p, 0);

        // Reject 0 and 1
        if (t0 == 0 && (y0 + Integer.MIN_VALUE) <= (1 + Integer.MIN_VALUE))
            return false;

        // Reject P - 1 and non-canonical encodings (i.e. >= P)
        if (t1 == 0 && (y0 + Integer.MIN_VALUE) >= (P[0] - 1 + Integer.MIN_VALUE))
            return false;

        return true;
    }

    private static boolean checkPointOrderVar(PointAffine p)
    {
        PointProjective r = new PointProjective();
        scalarMultOrderVar(p, r);
        return normalizeToNeutralElementVar(r);
    }

    private static boolean checkPointVar(byte[] p)
    {
        if ((p[POINT_BYTES - 1] & 0x7F) != 0x00)
        {
            return false;
        }
        if (Codec.decode32(p, 52) != P[13])
        {
            return true;
        }

        int[] t = new int[COORD_INTS];
        Codec.decode32(p, 0, t, 0, COORD_INTS);
        return !Nat.gte(COORD_INTS, t, P);
    }

    private static byte[] copy(byte[] buf, int off, int len)
    {
        byte[] result = new byte[len];
        System.arraycopy(buf, off, result, 0, len);
        return result;
    }

    public static Xof createPrehash()
    {
        return createXof();
    }

    private static Xof createXof()
    {
        return new SHAKEDigest(256);
    }

    private static boolean decodePointVar(byte[] p, boolean negate, PointAffine r)
    {
        int x_0 = (p[POINT_BYTES - 1] & 0x80) >>> 7;

        F.decode(p, r.y);

        int[] u = F.create();
        int[] v = F.create();

        F.sqr(r.y, u);
        F.mul(u, -C_d, v);
        F.negate(u, u);
        F.addOne(u);
        F.addOne(v);

        if (!F.sqrtRatioVar(u, v, r.x))
        {
            return false;
        }

        F.normalize(r.x);
        if (x_0 == 1 && F.isZeroVar(r.x))
        {
            return false;
        }

        if (negate ^ (x_0 != (r.x[0] & 1)))
        {
            F.negate(r.x, r.x);
            F.normalize(r.x);
        }

        return true;
    }

    private static void dom4(Xof d, byte phflag, byte[] ctx)
    {
//        assert ctx != null;

        int n = DOM4_PREFIX.length;
        byte[] t = new byte[n + 2 + ctx.length];
        System.arraycopy(DOM4_PREFIX, 0, t, 0, n);
        t[n] = phflag;
        t[n + 1] = (byte)ctx.length;
        System.arraycopy(ctx, 0, t, n + 2, ctx.length);

        d.update(t, 0, t.length);
    }

    private static void encodePoint(PointAffine p, byte[] r, int rOff)
    {
        F.encode(p.y, r, rOff);
        r[rOff + POINT_BYTES - 1] = (byte)((p.x[0] & 1) << 7);
    }

    public static void encodePublicPoint(PublicPoint publicPoint, byte[] pk, int pkOff)
    {
        F.encode(publicPoint.data, F.SIZE, pk, pkOff);
        pk[pkOff + POINT_BYTES - 1] = (byte)((publicPoint.data[0] & 1) << 7);
    }

    private static int encodeResult(PointProjective p, byte[] r, int rOff)
    {
        PointAffine q = new PointAffine();
        normalizeToAffine(p, q);

        int result = checkPoint(q);

        encodePoint(q, r, rOff);

        return result;
    }

    private static PublicPoint exportPoint(PointAffine p)
    {
        int[] data = new int[F.SIZE * 2];
        F.copy(p.x, 0, data, 0);
        F.copy(p.y, 0, data, F.SIZE);

        return new PublicPoint(data);
    }

    public static void generatePrivateKey(SecureRandom random, byte[] k)
    {
        if (k.length != SECRET_KEY_SIZE)
        {
            throw new IllegalArgumentException("k");
        }

        random.nextBytes(k);
    }

    public static void generatePublicKey(byte[] sk, int skOff, byte[] pk, int pkOff)
    {
        Xof d = createXof();
        byte[] h = new byte[SCALAR_BYTES * 2];

        d.update(sk, skOff, SECRET_KEY_SIZE);
        d.doFinal(h, 0, h.length);

        byte[] s = new byte[SCALAR_BYTES];
        pruneScalar(h, 0, s);

        scalarMultBaseEncoded(s, pk, pkOff);
    }

    public static PublicPoint generatePublicKey(byte[] sk, int skOff)
    {
        Xof d = createXof();
        byte[] h = new byte[SCALAR_BYTES * 2];

        d.update(sk, skOff, SECRET_KEY_SIZE);
        d.doFinal(h, 0, h.length);

        byte[] s = new byte[SCALAR_BYTES];
        pruneScalar(h, 0, s);

        PointProjective p = new PointProjective();
        scalarMultBase(s, p);

        PointAffine q = new PointAffine();
        normalizeToAffine(p, q);

        if (0 == checkPoint(q))
        {
            throw new IllegalStateException();
        }

        return exportPoint(q);
    }

    private static int getWindow4(int[] x, int n)
    {
        int w = n >>> 3, b = (n & 7) << 2;
        return (x[w] >>> b) & 15;
    }

    private static void implSign(Xof d, byte[] h, byte[] s, byte[] pk, int pkOff, byte[] ctx, byte phflag,
        byte[] m, int mOff, int mLen, byte[] sig, int sigOff)
    {
        dom4(d, phflag, ctx);
        d.update(h, SCALAR_BYTES, SCALAR_BYTES);
        d.update(m, mOff, mLen);
        d.doFinal(h, 0, h.length);

        byte[] r = Scalar448.reduce912(h);
        byte[] R = new byte[POINT_BYTES];
        scalarMultBaseEncoded(r, R, 0);

        dom4(d, phflag, ctx);
        d.update(R, 0, POINT_BYTES);
        d.update(pk, pkOff, POINT_BYTES);
        d.update(m, mOff, mLen);
        d.doFinal(h, 0, h.length);

        byte[] k = Scalar448.reduce912(h);
        byte[] S = calculateS(r, k, s);

        System.arraycopy(R, 0, sig, sigOff, POINT_BYTES);
        System.arraycopy(S, 0, sig, sigOff + POINT_BYTES, SCALAR_BYTES);
    }

    private static void implSign(byte[] sk, int skOff, byte[] ctx, byte phflag, byte[] m, int mOff, int mLen,
        byte[] sig, int sigOff)
    {
        if (!checkContextVar(ctx))
        {
            throw new IllegalArgumentException("ctx");
        }

        Xof d = createXof();
        byte[] h = new byte[SCALAR_BYTES * 2];

        d.update(sk, skOff, SECRET_KEY_SIZE);
        d.doFinal(h, 0, h.length);

        byte[] s = new byte[SCALAR_BYTES];
        pruneScalar(h, 0, s);

        byte[] pk = new byte[POINT_BYTES];
        scalarMultBaseEncoded(s, pk, 0);

        implSign(d, h, s, pk, 0, ctx, phflag, m, mOff, mLen, sig, sigOff);
    }

    private static void implSign(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] ctx, byte phflag,
        byte[] m, int mOff, int mLen, byte[] sig, int sigOff)
    {
        if (!checkContextVar(ctx))
        {
            throw new IllegalArgumentException("ctx");
        }

        Xof d = createXof();
        byte[] h = new byte[SCALAR_BYTES * 2];

        d.update(sk, skOff, SECRET_KEY_SIZE);
        d.doFinal(h, 0, h.length);

        byte[] s = new byte[SCALAR_BYTES];
        pruneScalar(h, 0, s);

        implSign(d, h, s, pk, pkOff, ctx, phflag, m, mOff, mLen, sig, sigOff);
    }

    private static boolean implVerify(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] ctx, byte phflag,
        byte[] m, int mOff, int mLen)
    {
        if (!checkContextVar(ctx))
        {
            throw new IllegalArgumentException("ctx");
        }

        byte[] R = copy(sig, sigOff, POINT_BYTES);
        byte[] S = copy(sig, sigOff + POINT_BYTES, SCALAR_BYTES);
        byte[] A = copy(pk, pkOff, PUBLIC_KEY_SIZE);

        if (!checkPointVar(R))
        {
            return false;
        }

        int[] nS = new int[SCALAR_INTS];
        if (!Scalar448.checkVar(S, nS))
        {
            return false;
        }

        if (!checkPointFullVar(A))
            return false;

        PointAffine pR = new PointAffine();
        if (!decodePointVar(R, true, pR))
        {
            return false;
        }

        PointAffine pA = new PointAffine();
        if (!decodePointVar(A, true, pA))
        {
            return false;
        }

        Xof d = createXof();
        byte[] h = new byte[SCALAR_BYTES * 2];

        dom4(d, phflag, ctx);
        d.update(R, 0, POINT_BYTES);
        d.update(A, 0, POINT_BYTES);
        d.update(m, mOff, mLen);
        d.doFinal(h, 0, h.length);

        byte[] k = Scalar448.reduce912(h);

        int[] nA = new int[SCALAR_INTS];
        Scalar448.decode(k, nA);

        int[] v0 = new int[8];
        int[] v1 = new int[8];
        Scalar448.reduceBasisVar(nA, v0, v1);
        Scalar448.multiply225Var(nS, v1, nS);

        PointProjective pZ = new PointProjective();
        scalarMultStraus225Var(nS, v0, pA, v1, pR, pZ);
        return normalizeToNeutralElementVar(pZ);
    }

    private static boolean implVerify(byte[] sig, int sigOff, PublicPoint publicPoint, byte[] ctx, byte phflag,
        byte[] m, int mOff, int mLen)
    {
        if (!checkContextVar(ctx))
        {
            throw new IllegalArgumentException("ctx");
        }

        byte[] R = copy(sig, sigOff, POINT_BYTES);
        byte[] S = copy(sig, sigOff + POINT_BYTES, SCALAR_BYTES);

        if (!checkPointVar(R))
        {
            return false;
        }

        int[] nS = new int[SCALAR_INTS];
        if (!Scalar448.checkVar(S, nS))
        {
            return false;
        }

        PointAffine pR = new PointAffine();
        if (!decodePointVar(R, true, pR))
        {
            return false;
        }

        PointAffine pA = new PointAffine();
        F.negate(publicPoint.data, pA.x);
        F.copy(publicPoint.data, F.SIZE, pA.y, 0);

        byte[] A = new byte[PUBLIC_KEY_SIZE];
        encodePublicPoint(publicPoint, A, 0);

        Xof d = createXof();
        byte[] h = new byte[SCALAR_BYTES * 2];

        dom4(d, phflag, ctx);
        d.update(R, 0, POINT_BYTES);
        d.update(A, 0, POINT_BYTES);
        d.update(m, mOff, mLen);
        d.doFinal(h, 0, h.length);

        byte[] k = Scalar448.reduce912(h);

        int[] nA = new int[SCALAR_INTS];
        Scalar448.decode(k, nA);

        int[] v0 = new int[8];
        int[] v1 = new int[8];
        Scalar448.reduceBasisVar(nA, v0, v1);
        Scalar448.multiply225Var(nS, v1, nS);

        PointProjective pZ = new PointProjective();
        scalarMultStraus225Var(nS, v0, pA, v1, pR, pZ);
        return normalizeToNeutralElementVar(pZ);
    }

    private static void invertZs(PointProjective[] points)
    {
        int count = points.length;
        int[] cs = F.createTable(count);

        int[] u = F.create();
        F.copy(points[0].z, 0, u, 0);
        F.copy(u, 0, cs, 0);

        int i = 0;
        while (++i < count)
        {
            F.mul(u, points[i].z, u);
            F.copy(u, 0, cs, i * F.SIZE);
        }

        F.invVar(u, u);
        --i;

        int[] t = F.create();

        while (i > 0)
        {
            int j = i--;
            F.copy(cs, i * F.SIZE, t, 0);
            F.mul(t, u, t);
            F.mul(u, points[j].z, u);
            F.copy(t, 0, points[j].z, 0);
        }

        F.copy(u, 0, points[0].z, 0);
    }

    private static void normalizeToAffine(PointProjective p, PointAffine r)
    {
        F.inv(p.z, r.y);
        F.mul(r.y, p.x, r.x);
        F.mul(r.y, p.y, r.y);
        F.normalize(r.x);
        F.normalize(r.y);
    }

    private static boolean normalizeToNeutralElementVar(PointProjective p)
    {
        F.normalize(p.x);
        F.normalize(p.y);
        F.normalize(p.z);

        return F.isZeroVar(p.x) && F.areEqualVar(p.y, p.z);
    }

    private static void pointAdd(PointAffine p, PointProjective r, PointTemp t)
    {
        int[] b = t.r1;
        int[] c = t.r2;
        int[] d = t.r3;
        int[] e = t.r4;
        int[] f = t.r5;
        int[] g = t.r6;
        int[] h = t.r7;

        F.sqr(r.z, b);
        F.mul(p.x, r.x, c);
        F.mul(p.y, r.y, d);
        F.mul(c, d, e);
        F.mul(e, -C_d, e);
//        F.apm(b, e, f, g);
        F.add(b, e, f);
        F.sub(b, e, g);
        F.add(p.y, p.x, h);
        F.add(r.y, r.x, e);
        F.mul(h, e, h);
//        F.apm(d, c, b, e);
        F.add(d, c, b);
        F.sub(d, c, e);
        F.carry(b);
        F.sub(h, b, h);
        F.mul(h, r.z, h);
        F.mul(e, r.z, e);
        F.mul(f, h, r.x);
        F.mul(e, g, r.y);
        F.mul(f, g, r.z);
    }

    private static void pointAdd(PointProjective p, PointProjective r, PointTemp t)
    {
        int[] a = t.r0;
        int[] b = t.r1;
        int[] c = t.r2;
        int[] d = t.r3;
        int[] e = t.r4;
        int[] f = t.r5;
        int[] g = t.r6;
        int[] h = t.r7;

        F.mul(p.z, r.z, a);
        F.sqr(a, b);
        F.mul(p.x, r.x, c);
        F.mul(p.y, r.y, d);
        F.mul(c, d, e);
        F.mul(e, -C_d, e);
//        F.apm(b, e, f, g);
        F.add(b, e, f);
        F.sub(b, e, g);
        F.add(p.y, p.x, h);
        F.add(r.y, r.x, e);
        F.mul(h, e, h);
//        F.apm(d, c, b, e);
        F.add(d, c, b);
        F.sub(d, c, e);
        F.carry(b);
        F.sub(h, b, h);
        F.mul(h, a, h);
        F.mul(e, a, e);
        F.mul(f, h, r.x);
        F.mul(e, g, r.y);
        F.mul(f, g, r.z);
    }

    private static void pointAddVar(boolean negate, PointAffine p, PointProjective r, PointTemp t)
    {
        int[] b = t.r1;
        int[] c = t.r2;
        int[] d = t.r3;
        int[] e = t.r4;
        int[] f = t.r5;
        int[] g = t.r6;
        int[] h = t.r7;

        int[] nb, ne, nf, ng;
        if (negate)
        {
            nb = e; ne = b; nf = g; ng = f;
            F.sub(p.y, p.x, h);
        }
        else
        {
            nb = b; ne = e; nf = f; ng = g;
            F.add(p.y, p.x, h);
        }

        F.sqr(r.z, b);
        F.mul(p.x, r.x, c);
        F.mul(p.y, r.y, d);
        F.mul(c, d, e);
        F.mul(e, -C_d, e);
//        F.apm(b, e, nf, ng);
        F.add(b, e, nf);
        F.sub(b, e, ng);
        F.add(r.y, r.x, e);
        F.mul(h, e, h);
//        F.apm(d, c, nb, e);
        F.add(d, c, nb);
        F.sub(d, c, ne);
        F.carry(nb);
        F.sub(h, b, h);
        F.mul(h, r.z, h);
        F.mul(e, r.z, e);
        F.mul(f, h, r.x);
        F.mul(e, g, r.y);
        F.mul(f, g, r.z);
    }

    private static void pointAddVar(boolean negate, PointProjective p, PointProjective r, PointTemp t)
    {
        int[] a = t.r0;
        int[] b = t.r1;
        int[] c = t.r2;
        int[] d = t.r3;
        int[] e = t.r4;
        int[] f = t.r5;
        int[] g = t.r6;
        int[] h = t.r7;

        int[] nb, ne, nf, ng;
        if (negate)
        {
            nb = e; ne = b; nf = g; ng = f;
            F.sub(p.y, p.x, h);
        }
        else
        {
            nb = b; ne = e; nf = f; ng = g;
            F.add(p.y, p.x, h);
        }

        F.mul(p.z, r.z, a);
        F.sqr(a, b);
        F.mul(p.x, r.x, c);
        F.mul(p.y, r.y, d);
        F.mul(c, d, e);
        F.mul(e, -C_d, e);
//        F.apm(b, e, nf, ng);
        F.add(b, e, nf);
        F.sub(b, e, ng);
        F.add(r.y, r.x, e);
        F.mul(h, e, h);
//        F.apm(d, c, nb, ne);
        F.add(d, c, nb);
        F.sub(d, c, ne);
        F.carry(nb);
        F.sub(h, b, h);
        F.mul(h, a, h);
        F.mul(e, a, e);
        F.mul(f, h, r.x);
        F.mul(e, g, r.y);
        F.mul(f, g, r.z);
    }

    private static void pointCopy(PointAffine p, PointProjective r)
    {
        F.copy(p.x, 0, r.x, 0);
        F.copy(p.y, 0, r.y, 0);
        F.one(r.z);
    }

    private static void pointCopy(PointProjective p, PointProjective r)
    {
        F.copy(p.x, 0, r.x, 0);
        F.copy(p.y, 0, r.y, 0);
        F.copy(p.z, 0, r.z, 0);
    }

    private static void pointDouble(PointProjective r, PointTemp t)
    {
        int[] b = t.r1;
        int[] c = t.r2;
        int[] d = t.r3;
        int[] e = t.r4;
        int[] h = t.r7;
        int[] j = t.r0;

        F.add(r.x, r.y, b);
        F.sqr(b, b);
        F.sqr(r.x, c);
        F.sqr(r.y, d);
        F.add(c, d, e);
        F.carry(e);
        F.sqr(r.z, h);
        F.add(h, h, h);
        F.carry(h);
        F.sub(e, h, j);
        F.sub(b, e, b);
        F.sub(c, d, c);
        F.mul(b, j, r.x);
        F.mul(e, c, r.y);
        F.mul(e, j, r.z);
    }

    private static void pointLookup(int block, int index, PointAffine p)
    {
//        assert 0 <= block && block < PRECOMP_BLOCKS;
//        assert 0 <= index && index < PRECOMP_POINTS;

        int off = block * PRECOMP_POINTS * 2 * F.SIZE;

        for (int i = 0; i < PRECOMP_POINTS; ++i)
        {
            int cond = ((i ^ index) - 1) >> 31;
            F.cmov(cond, PRECOMP_BASE_COMB, off, p.x, 0);     off += F.SIZE;
            F.cmov(cond, PRECOMP_BASE_COMB, off, p.y, 0);     off += F.SIZE;
        }
    }

    private static void pointLookup(int[] x, int n, int[] table, PointProjective r)
    {
        // TODO This method is currently hardcoded to 4-bit windows and 8 precomputed points

        int w = getWindow4(x, n);

        int sign = (w >>> (4 - 1)) ^ 1;
        int abs = (w ^ -sign) & 7;

//        assert sign == 0 || sign == 1;
//        assert 0 <= abs && abs < 8;

        for (int i = 0, off = 0; i < 8; ++i)
        {
            int cond = ((i ^ abs) - 1) >> 31;
            F.cmov(cond, table, off, r.x, 0);       off += F.SIZE;
            F.cmov(cond, table, off, r.y, 0);       off += F.SIZE;
            F.cmov(cond, table, off, r.z, 0);       off += F.SIZE;
        }

        F.cnegate(sign, r.x);
    }

    private static void pointLookup15(int[] table, PointProjective r)
    {
        int off = F.SIZE * 3 * 7;

        F.copy(table, off, r.x, 0);     off += F.SIZE;
        F.copy(table, off, r.y, 0);     off += F.SIZE;
        F.copy(table, off, r.z, 0);
    }

    private static int[] pointPrecompute(PointProjective p, int count, PointTemp t)
    {
//        assert count > 0;

        PointProjective q = new PointProjective();
        pointCopy(p, q);

        PointProjective d = new PointProjective();
        pointCopy(q, d);
        pointDouble(d, t);

        int[] table = F.createTable(count * 3);
        int off = 0;

        int i = 0;
        for (;;)
        {
            F.copy(q.x, 0, table, off);     off += F.SIZE;
            F.copy(q.y, 0, table, off);     off += F.SIZE;
            F.copy(q.z, 0, table, off);     off += F.SIZE;

            if (++i == count)
            {
                break;
            }

            pointAdd(d, q, t);
        }

        return table;
    }

    private static void pointPrecompute(PointAffine p, PointProjective[] points, int pointsOff, int pointsLen,
        PointTemp t)
    {
//        assert pointsLen > 0;

        PointProjective d = new PointProjective();
        pointCopy(p, d);
        pointDouble(d, t);

        points[pointsOff] = new PointProjective();
        pointCopy(p, points[pointsOff]);
        for (int i = 1; i < pointsLen; ++i)
        {
            points[pointsOff + i] = new PointProjective();
            pointCopy(points[pointsOff + i - 1], points[pointsOff + i]);
            pointAdd(d, points[pointsOff + i], t);
        }
    }

    private static void pointSetNeutral(PointProjective p)
    {
        F.zero(p.x);
        F.one(p.y);
        F.one(p.z);
    }

    public static void precompute()
    {
        synchronized (PRECOMP_LOCK)
        {
            if (PRECOMP_BASE_COMB != null)
            {
                return;
            }

//            assert PRECOMP_RANGE > 448;
//            assert PRECOMP_RANGE < 480;

            int wnafPoints = 1 << (WNAF_WIDTH_BASE - 2);
            int combPoints = PRECOMP_BLOCKS * PRECOMP_POINTS;
            int totalPoints = wnafPoints * 2 + combPoints;

            PointProjective[] points = new PointProjective[totalPoints];
            PointTemp t = new PointTemp();

            PointAffine B = new PointAffine();
            F.copy(B_x, 0, B.x, 0);
            F.copy(B_y, 0, B.y, 0);

            pointPrecompute(B, points, 0, wnafPoints, t);

            PointAffine B225 = new PointAffine();
            F.copy(B225_x, 0, B225.x, 0);
            F.copy(B225_y, 0, B225.y, 0);

            pointPrecompute(B225, points, wnafPoints, wnafPoints, t);

            PointProjective p = new PointProjective();
            pointCopy(B, p);

            int pointsIndex = wnafPoints * 2;
            PointProjective[] toothPowers = new PointProjective[PRECOMP_TEETH];
            for (int tooth = 0; tooth < PRECOMP_TEETH; ++tooth)
            {
                toothPowers[tooth] = new PointProjective();
            }

            for (int block = 0; block < PRECOMP_BLOCKS; ++block)
            {
                PointProjective sum = points[pointsIndex++] = new PointProjective();

                for (int tooth = 0; tooth < PRECOMP_TEETH; ++tooth)
                {
                    if (tooth == 0)
                    {
                        pointCopy(p, sum);
                    }
                    else
                    {
                        pointAdd(p, sum, t);
                    }

                    pointDouble(p, t);
                    pointCopy(p, toothPowers[tooth]);

                    if (block + tooth != PRECOMP_BLOCKS + PRECOMP_TEETH - 2)
                    {
                        for (int spacing = 1; spacing < PRECOMP_SPACING; ++spacing)
                        {
                            pointDouble(p, t);
                        }
                    }
                }

                F.negate(sum.x, sum.x);

                for (int tooth = 0; tooth < (PRECOMP_TEETH - 1); ++tooth)
                {
                    int size = 1 << tooth;
                    for (int j = 0; j < size; ++j, ++pointsIndex)
                    {
                        points[pointsIndex] = new PointProjective();
                        pointCopy(points[pointsIndex - size], points[pointsIndex]);
                        pointAdd(toothPowers[tooth], points[pointsIndex], t);
                    }
                }
            }
//            assert pointsIndex == totalPoints;

            invertZs(points);

            PRECOMP_BASE_WNAF = new PointAffine[wnafPoints];
            for (int i = 0; i < wnafPoints; ++i)
            {
                PointProjective q = points[i];
                PointAffine r = PRECOMP_BASE_WNAF[i] = new PointAffine();

                F.mul(q.x, q.z, r.x);       F.normalize(r.x);
                F.mul(q.y, q.z, r.y);       F.normalize(r.y);
            }

            PRECOMP_BASE225_WNAF = new PointAffine[wnafPoints];
            for (int i = 0; i < wnafPoints; ++i)
            {
                PointProjective q = points[wnafPoints + i];
                PointAffine r = PRECOMP_BASE225_WNAF[i] = new PointAffine();

                F.mul(q.x, q.z, r.x);       F.normalize(r.x);
                F.mul(q.y, q.z, r.y);       F.normalize(r.y);
            }

            PRECOMP_BASE_COMB = F.createTable(combPoints * 2);
            int off = 0;
            for (int i = wnafPoints * 2; i < totalPoints; ++i)
            {
                PointProjective q = points[i];

                F.mul(q.x, q.z, q.x);       F.normalize(q.x);
                F.mul(q.y, q.z, q.y);       F.normalize(q.y);

                F.copy(q.x, 0, PRECOMP_BASE_COMB, off);     off += F.SIZE;
                F.copy(q.y, 0, PRECOMP_BASE_COMB, off);     off += F.SIZE;
            }
//            assert off == PRECOMP_BASE_COMB.length;
        }
    }

    private static void pruneScalar(byte[] n, int nOff, byte[] r)
    {
        System.arraycopy(n, nOff, r, 0, SCALAR_BYTES - 1);

        r[0] &= 0xFC;
        r[SCALAR_BYTES - 2] |= 0x80;
        r[SCALAR_BYTES - 1]  = 0x00;
    }

    private static void scalarMult(byte[] k, PointProjective p, PointProjective r)
    {
        int[] n = new int[SCALAR_INTS + 1];
        Scalar448.decode(k, n);
        Scalar448.toSignedDigits(449, n, n);

        // NOTE: Bit 448 is handled explicitly by an initial addition
//        assert n[SCALAR_INTS] == 1;

        PointProjective q = new PointProjective();
        PointTemp t = new PointTemp();
        int[] table = pointPrecompute(p, 8, t);

        // Replace first 4 doublings (2^4 * P) with 1 addition (P + 15 * P)
        pointLookup15(table, r);
        pointAdd(p, r, t);

        int w = 111;
        for (;;)
        {
            pointLookup(n, w, table, q);
            pointAdd(q, r, t);

            if (--w < 0)
            {
                break;
            }

            for (int i = 0; i < 4; ++i)
            {
                pointDouble(r, t);
            }
        }
    }

    private static void scalarMultBase(byte[] k, PointProjective r)
    {
        // Equivalent (but much slower)
//        PointProjective p = new PointProjective();
//        F.copy(B_x, 0, p.x, 0);
//        F.copy(B_y, 0, p.y, 0);
//        F.one(p.z);
//        scalarMult(k, p, r);

        precompute();

        int[] n = new int[SCALAR_INTS + 1];
        Scalar448.decode(k, n);
        Scalar448.toSignedDigits(PRECOMP_RANGE, n, n);

        PointAffine p = new PointAffine();
        PointTemp t = new PointTemp();

        pointSetNeutral(r);

        int cOff = PRECOMP_SPACING - 1;
        for (;;)
        {
            int tPos = cOff;

            for (int block = 0; block < PRECOMP_BLOCKS; ++block)
            {
                int w = 0;
                for (int tooth = 0; tooth < PRECOMP_TEETH; ++tooth)
                {
                    int tBit = n[tPos >>> 5] >>> (tPos & 0x1F);
                    w &= ~(1 << tooth);
                    w ^= (tBit << tooth);
                    tPos += PRECOMP_SPACING;
                }

                int sign = (w >>> (PRECOMP_TEETH - 1)) & 1;
                int abs = (w ^ -sign) & PRECOMP_MASK;

//                assert sign == 0 || sign == 1;
//                assert 0 <= abs && abs < PRECOMP_POINTS;

                pointLookup(block, abs, p);

                F.cnegate(sign, p.x);

                pointAdd(p, r, t);
            }

            if (--cOff < 0)
            {
                break;
            }

            pointDouble(r, t);
        }
    }

    private static void scalarMultBaseEncoded(byte[] k, byte[] r, int rOff)
    {
        PointProjective p = new PointProjective();
        scalarMultBase(k, p);
        if (0 == encodeResult(p, r, rOff))
        {
            throw new IllegalStateException();
        }
    }

    /**
     * NOTE: Only for use by X448
     */
    public static void scalarMultBaseXY(X448.Friend friend, byte[] k, int kOff, int[] x, int[] y)
    {
        if (null == friend)
        {
            throw new NullPointerException("This method is only for use by X448");
        }

        byte[] n = new byte[SCALAR_BYTES];
        pruneScalar(k, kOff, n);

        PointProjective p = new PointProjective();
        scalarMultBase(n, p);
        if (0 == checkPoint(p))
        {
            throw new IllegalStateException();
        }

        F.copy(p.x, 0, x, 0);
        F.copy(p.y, 0, y, 0);
    }

    private static void scalarMultOrderVar(PointAffine p, PointProjective r)
    {
        byte[] ws_p = new byte[447];

        // NOTE: WNAF_WIDTH_225 because of the special structure of the order 
        Scalar448.getOrderWnafVar(WNAF_WIDTH_225, ws_p);

        int count = 1 << (WNAF_WIDTH_225 - 2);
        PointProjective[] tp = new PointProjective[count];
        PointTemp t = new PointTemp();
        pointPrecompute(p, tp, 0, count, t);

        pointSetNeutral(r);

        for (int bit = 446;;)
        {
            int wp = ws_p[bit];
            if (wp != 0)
            {
                int index = (wp >> 1) ^ (wp >> 31);
                pointAddVar(wp < 0, tp[index], r, t);
            }

            if (--bit < 0)
            {
                break;
            }

            pointDouble(r, t);
        }
    }

    private static void scalarMultStraus225Var(int[] nb, int[] np, PointAffine p, int[] nq, PointAffine q,
        PointProjective r)
    {
//        assert nb.length == SCALAR_INTS;
//        assert nb[SCALAR_INTS - 1] >>> 30 == 0;
//        assert np.length == 8;
//        assert np[7] >> 31 == np[7];
//        assert nq.length == 8;
//        assert nq[7] >> 31 == nq[7];

        precompute();

        byte[] ws_b = new byte[450];
        byte[] ws_p = new byte[225];
        byte[] ws_q = new byte[225];

        Wnaf.getSignedVar(nb, WNAF_WIDTH_BASE, ws_b);
        Wnaf.getSignedVar(np, WNAF_WIDTH_225, ws_p);
        Wnaf.getSignedVar(nq, WNAF_WIDTH_225, ws_q);

        int count = 1 << (WNAF_WIDTH_225 - 2);
        PointProjective[] tp = new PointProjective[count];
        PointProjective[] tq = new PointProjective[count];
        PointTemp t = new PointTemp();
        pointPrecompute(p, tp, 0, count, t);
        pointPrecompute(q, tq, 0, count, t);

        pointSetNeutral(r);

        int bit = 225;
        while (--bit >= 0)
        {
            if ((ws_b[bit] | ws_b[225 + bit] | ws_p[bit] | ws_q[bit]) != 0)
            {
                break;
            }
        }

        for (; bit >= 0; --bit)            
        {
            int wb = ws_b[bit];
            if (wb != 0)
            {
                int index = (wb >> 1) ^ (wb >> 31);
                pointAddVar(wb < 0, PRECOMP_BASE_WNAF[index], r, t);
            }

            int wb225 = ws_b[225 + bit];
            if (wb225 != 0)
            {
                int index = (wb225 >> 1) ^ (wb225 >> 31);
                pointAddVar(wb225 < 0, PRECOMP_BASE225_WNAF[index], r, t);
            }

            int wp = ws_p[bit];
            if (wp != 0)
            {
                int index = (wp >> 1) ^ (wp >> 31);
                pointAddVar(wp < 0, tp[index], r, t);
            }

            int wq = ws_q[bit];
            if (wq != 0)
            {
                int index = (wq >> 1) ^ (wq >> 31);
                pointAddVar(wq < 0, tq[index], r, t);
            }

            pointDouble(r, t);
        }

        // NOTE: Together with the final pointDouble of the loop, this clears the cofactor of 4
        pointDouble(r, t);
    }

    public static void sign(byte[] sk, int skOff, byte[] ctx, byte[] m, int mOff, int mLen, byte[] sig, int sigOff)
    {
        byte phflag = 0x00;

        implSign(sk, skOff, ctx, phflag, m, mOff, mLen, sig, sigOff);
    }

    public static void sign(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] ctx, byte[] m, int mOff, int mLen,
        byte[] sig, int sigOff)
    {
        byte phflag = 0x00;

        implSign(sk, skOff, pk, pkOff, ctx, phflag, m, mOff, mLen, sig, sigOff);
    }

    public static void signPrehash(byte[] sk, int skOff, byte[] ctx, byte[] ph, int phOff, byte[] sig, int sigOff)
    {
        byte phflag = 0x01;

        implSign(sk, skOff, ctx, phflag, ph, phOff, PREHASH_SIZE, sig, sigOff);
    }

    public static void signPrehash(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] ctx, byte[] ph, int phOff,
        byte[] sig, int sigOff)
    {
        byte phflag = 0x01;

        implSign(sk, skOff, pk, pkOff, ctx, phflag, ph, phOff, PREHASH_SIZE, sig, sigOff);
    }

    public static void signPrehash(byte[] sk, int skOff, byte[] ctx, Xof ph, byte[] sig, int sigOff)
    {
        byte[] m = new byte[PREHASH_SIZE];
        if (PREHASH_SIZE != ph.doFinal(m, 0, PREHASH_SIZE))
        {
            throw new IllegalArgumentException("ph");
        }

        byte phflag = 0x01;

        implSign(sk, skOff, ctx, phflag, m, 0, m.length, sig, sigOff);
    }

    public static void signPrehash(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] ctx, Xof ph, byte[] sig,
        int sigOff)
    {
        byte[] m = new byte[PREHASH_SIZE];
        if (PREHASH_SIZE != ph.doFinal(m, 0, PREHASH_SIZE))
        {
            throw new IllegalArgumentException("ph");
        }

        byte phflag = 0x01;

        implSign(sk, skOff, pk, pkOff, ctx, phflag, m, 0, m.length, sig, sigOff);
    }

    public static boolean validatePublicKeyFull(byte[] pk, int pkOff)
    {
        byte[] A = copy(pk, pkOff, PUBLIC_KEY_SIZE);

        if (!checkPointFullVar(A))
        {
            return false;
        }

        PointAffine pA = new PointAffine();
        if (!decodePointVar(A, false, pA))
        {
            return false;
        }

        return checkPointOrderVar(pA);
    }

    public static PublicPoint validatePublicKeyFullExport(byte[] pk, int pkOff)
    {
        byte[] A = copy(pk, pkOff, PUBLIC_KEY_SIZE);

        if (!checkPointFullVar(A))
        {
            return null;
        }

        PointAffine pA = new PointAffine();
        if (!decodePointVar(A, false, pA))
        {
            return null;
        }

        if (!checkPointOrderVar(pA))
        {
            return null;
        }

        return exportPoint(pA);
    }

    public static boolean validatePublicKeyPartial(byte[] pk, int pkOff)
    {
        byte[] A = copy(pk, pkOff, PUBLIC_KEY_SIZE);

        if (!checkPointFullVar(A))
        {
            return false;
        }

        PointAffine pA = new PointAffine();
        return decodePointVar(A, false, pA);
    }

    public static PublicPoint validatePublicKeyPartialExport(byte[] pk, int pkOff)
    {
        byte[] A = copy(pk, pkOff, PUBLIC_KEY_SIZE);

        if (!checkPointFullVar(A))
        {
            return null;
        }

        PointAffine pA = new PointAffine();
        if (!decodePointVar(A, false, pA))
        {
            return null;
        }

        return exportPoint(pA);
    }

    public static boolean verify(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] ctx, byte[] m, int mOff, int mLen)
    {
        byte phflag = 0x00;

        return implVerify(sig, sigOff, pk, pkOff, ctx, phflag, m, mOff, mLen);
    }

    public static boolean verify(byte[] sig, int sigOff, PublicPoint publicPoint, byte[] ctx, byte[] m, int mOff,
        int mLen)
    {
        byte phflag = 0x00;

        return implVerify(sig, sigOff, publicPoint, ctx, phflag, m, mOff, mLen);
    }

    public static boolean verifyPrehash(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] ctx, byte[] ph, int phOff)
    {
        byte phflag = 0x01;

        return implVerify(sig, sigOff, pk, pkOff, ctx, phflag, ph, phOff, PREHASH_SIZE);
    }

    public static boolean verifyPrehash(byte[] sig, int sigOff, PublicPoint publicPoint, byte[] ctx, byte[] ph,
        int phOff)
    {
        byte phflag = 0x01;

        return implVerify(sig, sigOff, publicPoint, ctx, phflag, ph, phOff, PREHASH_SIZE);
    }

    public static boolean verifyPrehash(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] ctx, Xof ph)
    {
        byte[] m = new byte[PREHASH_SIZE];
        if (PREHASH_SIZE != ph.doFinal(m, 0, PREHASH_SIZE))
        {
            throw new IllegalArgumentException("ph");
        }

        byte phflag = 0x01;

        return implVerify(sig, sigOff, pk, pkOff, ctx, phflag, m, 0, m.length);
    }

    public static boolean verifyPrehash(byte[] sig, int sigOff, PublicPoint publicPoint, byte[] ctx, Xof ph)
    {
        byte[] m = new byte[PREHASH_SIZE];
        if (PREHASH_SIZE != ph.doFinal(m, 0, PREHASH_SIZE))
        {
            throw new IllegalArgumentException("ph");
        }

        byte phflag = 0x01;

        return implVerify(sig, sigOff, publicPoint, ctx, phflag, m, 0, m.length);
    }
}
