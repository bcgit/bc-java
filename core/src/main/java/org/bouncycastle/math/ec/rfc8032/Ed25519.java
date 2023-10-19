package org.bouncycastle.math.ec.rfc8032;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.math.ec.rfc7748.X25519Field;
import org.bouncycastle.math.raw.Interleave;
import org.bouncycastle.math.raw.Nat256;

/**
 * A low-level implementation of the Ed25519, Ed25519ctx, and Ed25519ph instantiations of the Edwards-Curve
 * Digital Signature Algorithm specified in <a href="https://www.rfc-editor.org/rfc/rfc8032">RFC 8032</a>.
 * <p>
 * The implementation strategy is mostly drawn from <a href="https://ia.cr/2012/309"> Mike Hamburg, "Fast and
 * compact elliptic-curve cryptography"</a>, notably the "signed multi-comb" algorithm (for scalar
 * multiplication by a fixed point), the "half Niels coordinates" (for precomputed points), and the
 * "extensible coordinates" (for accumulators). Standard
 * <a href="https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html">extended coordinates</a> are used
 * during precomputations, needing only a single extra point addition formula.
 */
public abstract class Ed25519
{
    // -x^2 + y^2 == 1 + 0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3 * x^2 * y^2

    public static final class Algorithm
    {
        public static final int Ed25519 = 0;
        public static final int Ed25519ctx = 1;
        public static final int Ed25519ph = 2;
    }

    public static final class PublicPoint
    {
        final int[] data;

        PublicPoint(int[] data)
        {
            this.data = data;
        }
    }

    private static class F extends X25519Field {};

    private static final int COORD_INTS = 8;
    private static final int POINT_BYTES = COORD_INTS * 4;
    private static final int SCALAR_INTS = 8;
    private static final int SCALAR_BYTES = SCALAR_INTS * 4;

    public static final int PREHASH_SIZE = 64;
    public static final int PUBLIC_KEY_SIZE = POINT_BYTES;
    public static final int SECRET_KEY_SIZE = 32;
    public static final int SIGNATURE_SIZE = POINT_BYTES + SCALAR_BYTES;

    // "SigEd25519 no Ed25519 collisions"
    private static final byte[] DOM2_PREFIX = new byte[]{ 0x53, 0x69, 0x67, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39,
        0x20, 0x6e, 0x6f, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x63, 0x6f, 0x6c, 0x6c, 0x69, 0x73,
        0x69, 0x6f, 0x6e, 0x73 };

    private static final int[] P = new int[]{ 0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0x7FFFFFFF };

    private static final int[] ORDER8_y1 = new int[]{ 0x706A17C7, 0x4FD84D3D, 0x760B3CBA, 0x0F67100D, 0xFA53202A,
        0xC6CC392C, 0x77FDC74E, 0x7A03AC92 };
    private static final int[] ORDER8_y2 = new int[]{ 0x8F95E826, 0xB027B2C2, 0x89F4C345, 0xF098EFF2, 0x05ACDFD5,
        0x3933C6D3, 0x880238B1, 0x05FC536D };

    private static final int[] B_x = new int[]{ 0x0325D51A, 0x018B5823, 0x007B2C95, 0x0304A92D, 0x00D2598E, 0x01D6DC5C,
        0x01388C7F, 0x013FEC0A, 0x029E6B72, 0x0042D26D };
    private static final int[] B_y = new int[]{ 0x02666658, 0x01999999, 0x00666666, 0x03333333, 0x00CCCCCC, 0x02666666,
        0x01999999, 0x00666666, 0x03333333, 0x00CCCCCC, };

    // 2^128 * B
    private static final int[] B128_x = new int[]{ 0x00B7E824, 0x0011EB98, 0x003E5FC8, 0x024E1739, 0x0131CD0B,
        0x014E29A0, 0x034E6138, 0x0132C952, 0x03F9E22F, 0x00984F5F };
    private static final int[] B128_y = new int[]{ 0x03F5A66B, 0x02AF4452, 0x0049E5BB, 0x00F28D26, 0x0121A17C,
        0x02C29C3A, 0x0047AD89, 0x0087D95F, 0x0332936E, 0x00BE5933 };

    // Note that d == -121665/121666
    private static final int[] C_d = new int[]{ 0x035978A3, 0x02D37284, 0x018AB75E, 0x026A0A0E, 0x0000E014, 0x0379E898,
        0x01D01E5D, 0x01E738CC, 0x03715B7F, 0x00A406D9 };
    private static final int[] C_d2 = new int[]{ 0x02B2F159, 0x01A6E509, 0x01156EBD, 0x00D4141D, 0x0001C029, 0x02F3D130,
        0x03A03CBB, 0x01CE7198, 0x02E2B6FF, 0x00480DB3 };
    private static final int[] C_d4 = new int[]{ 0x0165E2B2, 0x034DCA13, 0x002ADD7A, 0x01A8283B, 0x00038052, 0x01E7A260,
        0x03407977, 0x019CE331, 0x01C56DFF, 0x00901B67 };

//    private static final int WNAF_WIDTH = 5;
    private static final int WNAF_WIDTH_128 = 4;
    private static final int WNAF_WIDTH_BASE = 6;

    // scalarMultBase is hard-coded for these values of blocks, teeth, spacing so they can't be freely changed
    private static final int PRECOMP_BLOCKS = 8;
    private static final int PRECOMP_TEETH = 4;
    private static final int PRECOMP_SPACING = 8;
    private static final int PRECOMP_RANGE = PRECOMP_BLOCKS * PRECOMP_TEETH * PRECOMP_SPACING; // range == 256
    private static final int PRECOMP_POINTS = 1 << (PRECOMP_TEETH - 1);
    private static final int PRECOMP_MASK = PRECOMP_POINTS - 1;

    private static final Object PRECOMP_LOCK = new Object();
    private static PointPrecomp[] PRECOMP_BASE_WNAF = null;
    private static PointPrecomp[] PRECOMP_BASE128_WNAF = null;    
    private static int[] PRECOMP_BASE_COMB = null;

    private static class PointAccum
    {
        int[] x = F.create();
        int[] y = F.create();
        int[] z = F.create();
        int[] u = F.create();
        int[] v = F.create();
    }

    private static class PointAffine
    {
        int[] x = F.create();
        int[] y = F.create();
    }

    private static class PointExtended
    {
        int[] x = F.create();
        int[] y = F.create();
        int[] z = F.create();
        int[] t = F.create();
    }

    private static class PointPrecomp
    {
        int[] ymx_h = F.create();       // (y - x)/2
        int[] ypx_h = F.create();       // (y + x)/2
        int[] xyd = F.create();         // x.y.d
    }

    private static class PointPrecompZ
    {
        int[] ymx_h = F.create();       // (y - x)/2
        int[] ypx_h = F.create();       // (y + x)/2
        int[] xyd = F.create();         // x.y.d
        int[] z = F.create();
    }

    // Temp space to avoid allocations in point formulae.
    private static class PointTemp
    {
        int[] r0 = F.create();
        int[] r1 = F.create();;
    }

    private static byte[] calculateS(byte[] r, byte[] k, byte[] s)
    {
        int[] t = new int[SCALAR_INTS * 2];     Scalar25519.decode(r, t);
        int[] u = new int[SCALAR_INTS];         Scalar25519.decode(k, u);
        int[] v = new int[SCALAR_INTS];         Scalar25519.decode(s, v);

        Nat256.mulAddTo(u, v, t);

        byte[] result = new byte[SCALAR_BYTES * 2];
        Codec.encode32(t, 0, t.length, result, 0);
        return Scalar25519.reduce512(result);
    }

    private static boolean checkContextVar(byte[] ctx , byte phflag)
    {
        return ctx == null && phflag == 0x00 
            || ctx != null && ctx.length < 256;
    }

    private static int checkPoint(PointAffine p)
    {
        int[] t = F.create();
        int[] u = F.create();
        int[] v = F.create();

        F.sqr(p.x, u);
        F.sqr(p.y, v);
        F.mul(u, v, t);
        F.sub(v, u, v);
        F.mul(t, C_d, t);
        F.addOne(t);
        F.sub(t, v, t);
        F.normalize(t);

        return F.isZero(t);
    }

    private static int checkPoint(PointAccum p)
    {
        int[] t = F.create();
        int[] u = F.create();
        int[] v = F.create();
        int[] w = F.create();

        F.sqr(p.x, u);
        F.sqr(p.y, v);
        F.sqr(p.z, w);
        F.mul(u, v, t);
        F.sub(v, u, v);
        F.mul(v, w, v);
        F.sqr(w, w);
        F.mul(t, C_d, t);
        F.add(t, w, t);
        F.sub(t, v, t);
        F.normalize(t);

        return F.isZero(t);
    }

    private static boolean checkPointFullVar(byte[] p)
    {
        int y7 = Codec.decode32(p, 28) & 0x7FFFFFFF;

        int t0 = y7;
        int t1 = y7 ^ P[7];
        int t2 = y7 ^ ORDER8_y1[7];
        int t3 = y7 ^ ORDER8_y2[7];

        for (int i = COORD_INTS - 2; i > 0; --i)
        {
            int yi = Codec.decode32(p, i * 4);

            t0 |= yi;
            t1 |= yi ^ P[i];
            t2 |= yi ^ ORDER8_y1[i];
            t3 |= yi ^ ORDER8_y2[i];
        }

        int y0 = Codec.decode32(p, 0);

        // Reject 0 and 1
        if (t0 == 0 && (y0 + Integer.MIN_VALUE) <= (1 + Integer.MIN_VALUE))
            return false;

        // Reject P - 1 and non-canonical encodings (i.e. >= P)
        if (t1 == 0 && (y0 + Integer.MIN_VALUE) >= (P[0] - 1 + Integer.MIN_VALUE))
            return false;

        t2 |= y0 ^ ORDER8_y1[0];
        t3 |= y0 ^ ORDER8_y2[0];

        // Reject order 8 points
        return (t2 != 0) & (t3 != 0);
    }

    private static boolean checkPointOrderVar(PointAffine p)
    {
        PointAccum r = new PointAccum();
        scalarMultOrderVar(p, r);
        return normalizeToNeutralElementVar(r);
    }

    private static boolean checkPointVar(byte[] p)
    {
        if ((Codec.decode32(p, 28) & 0x7FFFFFFF) < P[7])
        {
            return true;
        }

        int[] t = new int[COORD_INTS];
        Codec.decode32(p, 0, t, 0, COORD_INTS);
        t[COORD_INTS - 1] &= 0x7FFFFFFF;
        return !Nat256.gte(t, P);
    }

    private static byte[] copy(byte[] buf, int off, int len)
    {
        byte[] result = new byte[len];
        System.arraycopy(buf, off, result, 0, len);
        return result;
    }

    private static Digest createDigest()
    {
        Digest d = new SHA512Digest();
        if (d.getDigestSize() != 64)
        {
            throw new IllegalStateException();
        }
        return d;
    }

    public static Digest createPrehash()
    {
        return createDigest();
    }

    private static boolean decodePointVar(byte[] p, boolean negate, PointAffine r)
    {
        int x_0 = (p[POINT_BYTES - 1] & 0x80) >>> 7;

        F.decode(p, r.y);

        int[] u = F.create();
        int[] v = F.create();

        F.sqr(r.y, u);
        F.mul(C_d, u, v);
        F.subOne(u);
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

    private static void dom2(Digest d, byte phflag, byte[] ctx)
    {
//        assert ctx != null;

        int n = DOM2_PREFIX.length;
        byte[] t = new byte[n + 2 + ctx.length];
        System.arraycopy(DOM2_PREFIX, 0, t, 0, n);
        t[n] = phflag;
        t[n + 1] = (byte)ctx.length;
        System.arraycopy(ctx, 0, t, n + 2, ctx.length);

        d.update(t, 0, t.length);
    }

    private static void encodePoint(PointAffine p, byte[] r, int rOff)
    {
        F.encode(p.y, r, rOff);
        r[rOff + POINT_BYTES - 1] |= (p.x[0] & 1) << 7;
    }

    public static void encodePublicPoint(PublicPoint publicPoint, byte[] pk, int pkOff)
    {
        F.encode(publicPoint.data, F.SIZE, pk, pkOff);
        pk[pkOff + POINT_BYTES - 1] |= (publicPoint.data[0] & 1) << 7;
    }

    private static int encodeResult(PointAccum p, byte[] r, int rOff)
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
        Digest d = createDigest();
        byte[] h = new byte[64];

        d.update(sk, skOff, SECRET_KEY_SIZE);
        d.doFinal(h, 0);

        byte[] s = new byte[SCALAR_BYTES];
        pruneScalar(h, 0, s);

        scalarMultBaseEncoded(s, pk, pkOff);
    }

    public static PublicPoint generatePublicKey(byte[] sk, int skOff)
    {
        Digest d = createDigest();
        byte[] h = new byte[64];

        d.update(sk, skOff, SECRET_KEY_SIZE);
        d.doFinal(h, 0);

        byte[] s = new byte[SCALAR_BYTES];
        pruneScalar(h, 0, s);

        PointAccum p = new PointAccum();
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

    private static void groupCombBits(int[] n)
    {
        /*
         * Because we are using 4 teeth and 8 spacing, each limb of n corresponds to one of the 8 blocks.
         * Therefore we can efficiently group the bits for each comb position using a (double) shuffle. 
         */
        for (int i = 0; i < n.length; ++i)
        {
            n[i] = Interleave.shuffle2(n[i]);
        }
    }

    private static void implSign(Digest d, byte[] h, byte[] s, byte[] pk, int pkOff, byte[] ctx, byte phflag, byte[] m,
        int mOff, int mLen, byte[] sig, int sigOff)
    {
        if (ctx != null)
        {
            dom2(d, phflag, ctx);
        }
        d.update(h, SCALAR_BYTES, SCALAR_BYTES);
        d.update(m, mOff, mLen);
        d.doFinal(h, 0);

        byte[] r = Scalar25519.reduce512(h);
        byte[] R = new byte[POINT_BYTES];
        scalarMultBaseEncoded(r, R, 0);

        if (ctx != null)
        {
            dom2(d, phflag, ctx);
        }
        d.update(R, 0, POINT_BYTES);
        d.update(pk, pkOff, POINT_BYTES);
        d.update(m, mOff, mLen);
        d.doFinal(h, 0);

        byte[] k = Scalar25519.reduce512(h);
        byte[] S = calculateS(r, k, s);

        System.arraycopy(R, 0, sig, sigOff, POINT_BYTES);
        System.arraycopy(S, 0, sig, sigOff + POINT_BYTES, SCALAR_BYTES);
    }

    private static void implSign(byte[] sk, int skOff, byte[] ctx, byte phflag, byte[] m, int mOff, int mLen,
        byte[] sig, int sigOff)
    {
        if (!checkContextVar(ctx, phflag))
        {
            throw new IllegalArgumentException("ctx");
        }

        Digest d = createDigest();
        byte[] h = new byte[64];

        d.update(sk, skOff, SECRET_KEY_SIZE);
        d.doFinal(h, 0);

        byte[] s = new byte[SCALAR_BYTES];
        pruneScalar(h, 0, s);

        byte[] pk = new byte[POINT_BYTES];
        scalarMultBaseEncoded(s, pk, 0);

        implSign(d, h, s, pk, 0, ctx, phflag, m, mOff, mLen, sig, sigOff);
    }

    private static void implSign(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] ctx, byte phflag,
        byte[] m, int mOff, int mLen, byte[] sig, int sigOff)
    {
        if (!checkContextVar(ctx, phflag))
        {
            throw new IllegalArgumentException("ctx");
        }

        Digest d = createDigest();
        byte[] h = new byte[64];

        d.update(sk, skOff, SECRET_KEY_SIZE);
        d.doFinal(h, 0);

        byte[] s = new byte[SCALAR_BYTES];
        pruneScalar(h, 0, s);

        implSign(d, h, s, pk, pkOff, ctx, phflag, m, mOff, mLen, sig, sigOff);
    }

    private static boolean implVerify(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] ctx, byte phflag, byte[] m,
        int mOff, int mLen)
    {
        if (!checkContextVar(ctx, phflag))
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
        if (!Scalar25519.checkVar(S, nS))
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

        Digest d = createDigest();
        byte[] h = new byte[64];

        if (ctx != null)
        {
            dom2(d, phflag, ctx);
        }
        d.update(R, 0, POINT_BYTES);
        d.update(A, 0, POINT_BYTES);
        d.update(m, mOff, mLen);
        d.doFinal(h, 0);

        byte[] k = Scalar25519.reduce512(h);

        int[] nA = new int[SCALAR_INTS];
        Scalar25519.decode(k, nA);

        int[] v0 = new int[4];
        int[] v1 = new int[4];
        Scalar25519.reduceBasisVar(nA, v0, v1);
        Scalar25519.multiply128Var(nS, v1, nS);

        PointAccum pZ = new PointAccum();
        scalarMultStraus128Var(nS, v0, pA, v1, pR, pZ);
        return normalizeToNeutralElementVar(pZ);
    }

    private static boolean implVerify(byte[] sig, int sigOff, PublicPoint publicPoint, byte[] ctx, byte phflag,
        byte[] m, int mOff, int mLen)
    {
        if (!checkContextVar(ctx, phflag))
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
        if (!Scalar25519.checkVar(S, nS))
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

        Digest d = createDigest();
        byte[] h = new byte[64];

        if (ctx != null)
        {
            dom2(d, phflag, ctx);
        }
        d.update(R, 0, POINT_BYTES);
        d.update(A, 0, POINT_BYTES);
        d.update(m, mOff, mLen);
        d.doFinal(h, 0);

        byte[] k = Scalar25519.reduce512(h);

        int[] nA = new int[SCALAR_INTS];
        Scalar25519.decode(k, nA);

        int[] v0 = new int[4];
        int[] v1 = new int[4];
        Scalar25519.reduceBasisVar(nA, v0, v1);
        Scalar25519.multiply128Var(nS, v1, nS);

        PointAccum pZ = new PointAccum();
        scalarMultStraus128Var(nS, v0, pA, v1, pR, pZ);
        return normalizeToNeutralElementVar(pZ);
    }

    private static void invertDoubleZs(PointExtended[] points)
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

        F.add(u, u, u);
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

    private static void normalizeToAffine(PointAccum p, PointAffine r)
    {
        F.inv(p.z, r.y);
        F.mul(r.y, p.x, r.x);
        F.mul(r.y, p.y, r.y);
        F.normalize(r.x);
        F.normalize(r.y);
    }

    private static boolean normalizeToNeutralElementVar(PointAccum p)
    {
        F.normalize(p.x);
        F.normalize(p.y);
        F.normalize(p.z);

        return F.isZeroVar(p.x) && F.areEqualVar(p.y, p.z);
    }

    private static void pointAdd(PointExtended p, PointExtended q, PointExtended r, PointTemp t)
    {
        // p may ref the same point as r (or q), but q may not ref the same point as r.
//        assert q != r;

        int[] a = r.x;
        int[] b = r.y;
        int[] c = t.r0;
        int[] d = t.r1;
        int[] e = a;
        int[] f = c;
        int[] g = d;
        int[] h = b;

        F.apm(p.y, p.x, b, a);
        F.apm(q.y, q.x, d, c);
        F.mul(a, c, a);
        F.mul(b, d, b);
        F.mul(p.t, q.t, c);
        F.mul(c, C_d2, c);
        F.add(p.z, p.z, d);
        F.mul(d, q.z, d);
        F.apm(b, a, h, e);
        F.apm(d, c, g, f);
        F.mul(e, h, r.t);
        F.mul(f, g, r.z);
        F.mul(e, f, r.x);
        F.mul(h, g, r.y);
    }

    private static void pointAdd(PointPrecomp p, PointAccum r, PointTemp t)
    {
        int[] a = r.x;
        int[] b = r.y;
        int[] c = t.r0;
        int[] e = r.u;
        int[] f = a;
        int[] g = b;
        int[] h = r.v;

        F.apm(r.y, r.x, b, a);
        F.mul(a, p.ymx_h, a);
        F.mul(b, p.ypx_h, b);
        F.mul(r.u, r.v, c);
        F.mul(c, p.xyd, c);
        F.apm(b, a, h, e);
        F.apm(r.z, c, g, f);
        F.mul(f, g, r.z);
        F.mul(f, e, r.x);
        F.mul(g, h, r.y);
    }

    private static void pointAdd(PointPrecompZ p, PointAccum r, PointTemp t)
    {
        int[] a = r.x;
        int[] b = r.y;
        int[] c = t.r0;
        int[] d = r.z;
        int[] e = r.u;
        int[] f = a;
        int[] g = b;
        int[] h = r.v;

        F.apm(r.y, r.x, b, a);
        F.mul(a, p.ymx_h, a);
        F.mul(b, p.ypx_h, b);
        F.mul(r.u, r.v, c);
        F.mul(c, p.xyd, c);
        F.mul(r.z, p.z, d);
        F.apm(b, a, h, e);
        F.apm(d, c, g, f);
        F.mul(f, g, r.z);
        F.mul(f, e, r.x);
        F.mul(g, h, r.y);
    }

    private static void pointAddVar(boolean negate, PointPrecomp p, PointAccum r, PointTemp t)
    {
        int[] a = r.x;
        int[] b = r.y;
        int[] c = t.r0;
        int[] e = r.u;
        int[] f = a;
        int[] g = b;
        int[] h = r.v;

        int[] na, nb;
        if (negate)
        {
            na = b; nb = a;
        }
        else
        {
            na = a; nb = b;
        }
        int[] nf = na, ng = nb;

        F.apm(r.y, r.x, b, a);
        F.mul(na, p.ymx_h, na);
        F.mul(nb, p.ypx_h, nb);
        F.mul(r.u, r.v, c);
        F.mul(c, p.xyd, c);
        F.apm(b, a, h, e);
        F.apm(r.z, c, ng, nf);
        F.mul(f, g, r.z);
        F.mul(f, e, r.x);
        F.mul(g, h, r.y);
    }

    private static void pointAddVar(boolean negate, PointPrecompZ p, PointAccum r, PointTemp t)
    {
        int[] a = r.x;
        int[] b = r.y;
        int[] c = t.r0;
        int[] d = r.z;
        int[] e = r.u;
        int[] f = a;
        int[] g = b;
        int[] h = r.v;

        int[] na, nb;
        if (negate)
        {
            na = b; nb = a;
        }
        else
        {
            na = a; nb = b;
        }
        int[] nf = na, ng = nb;

        F.apm(r.y, r.x, b, a);
        F.mul(na, p.ymx_h, na);
        F.mul(nb, p.ypx_h, nb);
        F.mul(r.u, r.v, c);
        F.mul(c, p.xyd, c);
        F.mul(r.z, p.z, d);
        F.apm(b, a, h, e);
        F.apm(d, c, ng, nf);
        F.mul(f, g, r.z);
        F.mul(f, e, r.x);
        F.mul(g, h, r.y);
    }

    private static void pointCopy(PointAccum p, PointExtended r)
    {
        F.copy(p.x, 0, r.x, 0);
        F.copy(p.y, 0, r.y, 0);
        F.copy(p.z, 0, r.z, 0);
        F.mul(p.u, p.v, r.t);
    }

    private static void pointCopy(PointAffine p, PointExtended r)
    {
        F.copy(p.x, 0, r.x, 0);
        F.copy(p.y, 0, r.y, 0);
        F.one(r.z);
        F.mul(p.x, p.y, r.t);
    }

    private static void pointCopy(PointExtended p, PointPrecompZ r)
    {
        // To avoid halving x and y, we double t and z instead.
        F.apm(p.y, p.x, r.ypx_h, r.ymx_h);
        F.mul(p.t, C_d2, r.xyd);
        F.add(p.z, p.z, r.z);
    }

    private static void pointDouble(PointAccum r)
    {
        int[] a = r.x;
        int[] b = r.y;
        int[] c = r.z;
        int[] e = r.u;
        int[] f = a;
        int[] g = b;
        int[] h = r.v;

        F.add(r.x, r.y, e);
        F.sqr(r.x, a);
        F.sqr(r.y, b);
        F.sqr(r.z, c);
        F.add(c, c, c);
        F.apm(a, b, h, g);
        F.sqr(e, e);
        F.sub(h, e, e);
        F.add(c, g, f);
        F.carry(f); // Probably unnecessary, but keep until better bounds analysis available
        F.mul(f, g, r.z);
        F.mul(f, e, r.x);
        F.mul(g, h, r.y);
    }

    private static void pointLookup(int block, int index, PointPrecomp p)
    {
//        assert 0 <= block && block < PRECOMP_BLOCKS;
//        assert 0 <= index && index < PRECOMP_POINTS;

        int off = block * PRECOMP_POINTS * 3 * F.SIZE;

        for (int i = 0; i < PRECOMP_POINTS; ++i)
        {
            int cond = ((i ^ index) - 1) >> 31;
            F.cmov(cond, PRECOMP_BASE_COMB, off, p.ymx_h, 0);     off += F.SIZE;
            F.cmov(cond, PRECOMP_BASE_COMB, off, p.ypx_h, 0);     off += F.SIZE;
            F.cmov(cond, PRECOMP_BASE_COMB, off, p.xyd,   0);     off += F.SIZE;
        }
    }

    private static void pointLookupZ(int[] x, int n, int[] table, PointPrecompZ r)
    {
        // TODO This method is currently hard-coded to 4-bit windows and 8 precomputed points

        int w = getWindow4(x, n);

        int sign = (w >>> (4 - 1)) ^ 1;
        int abs = (w ^ -sign) & 7;

//        assert sign == 0 || sign == 1;
//        assert 0 <= abs && abs < 8;

        for (int i = 0, off = 0; i < 8; ++i)
        {
            int cond = ((i ^ abs) - 1) >> 31;
            F.cmov(cond, table, off, r.ymx_h, 0);       off += F.SIZE;
            F.cmov(cond, table, off, r.ypx_h, 0);       off += F.SIZE;
            F.cmov(cond, table, off, r.xyd  , 0);       off += F.SIZE;
            F.cmov(cond, table, off, r.z    , 0);       off += F.SIZE;
        }

        F.cswap(sign, r.ymx_h, r.ypx_h);
        F.cnegate(sign, r.xyd);
    }

    private static void pointPrecompute(PointAffine p, PointExtended[] points, int pointsOff, int pointsLen,
        PointTemp t)
    {
//        assert pointsLen > 0;

        pointCopy(p, points[pointsOff] = new PointExtended());

        PointExtended d = new PointExtended();
        pointAdd(points[pointsOff], points[pointsOff], d, t);

        for (int i = 1; i < pointsLen; ++i)
        {
            pointAdd(points[pointsOff + i - 1], d, points[pointsOff + i] = new PointExtended(), t);
        }
    }

    private static int[] pointPrecomputeZ(PointAffine p, int count, PointTemp t)
    {
//        assert count > 0;

        PointExtended q = new PointExtended();
        pointCopy(p, q);

        PointExtended d = new PointExtended();
        pointAdd(q, q, d, t);

        PointPrecompZ r = new PointPrecompZ();
        int[] table = F.createTable(count * 4);
        int off = 0;

        int i = 0;
        for (;;)
        {
            pointCopy(q, r);

            F.copy(r.ymx_h, 0, table, off);     off += F.SIZE;
            F.copy(r.ypx_h, 0, table, off);     off += F.SIZE;
            F.copy(r.xyd  , 0, table, off);     off += F.SIZE;
            F.copy(r.z    , 0, table, off);     off += F.SIZE;

            if (++i == count)
            {
                break;
            }

            pointAdd(q, d, q, t);
        }

        return table;
    }

    private static void pointPrecomputeZ(PointAffine p, PointPrecompZ[] points, int count, PointTemp t)
    {
//        assert count > 0;

        PointExtended q = new PointExtended();
        pointCopy(p, q);

        PointExtended d = new PointExtended();
        pointAdd(q, q, d, t);

        int i = 0;
        for (;;)
        {
            PointPrecompZ r = points[i] = new PointPrecompZ();
            pointCopy(q, r);

            if (++i == count)
            {
                break;
            }

            pointAdd(q, d, q, t);
        }
    }

    private static void pointSetNeutral(PointAccum p)
    {
        F.zero(p.x);
        F.one(p.y);
        F.one(p.z);
        F.zero(p.u);
        F.one(p.v);
    }

    public static void precompute()
    {
        synchronized (PRECOMP_LOCK)
        {
            if (PRECOMP_BASE_COMB != null)
            {
                return;
            }

            int wnafPoints = 1 << (WNAF_WIDTH_BASE - 2);
            int combPoints = PRECOMP_BLOCKS * PRECOMP_POINTS;
            int totalPoints = wnafPoints * 2 + combPoints;

            PointExtended[] points = new PointExtended[totalPoints];
            PointTemp t = new PointTemp();

            PointAffine B = new PointAffine();
            F.copy(B_x, 0, B.x, 0);
            F.copy(B_y, 0, B.y, 0);

            pointPrecompute(B, points, 0, wnafPoints, t);

            PointAffine B128 = new PointAffine();
            F.copy(B128_x, 0, B128.x, 0);
            F.copy(B128_y, 0, B128.y, 0);

            pointPrecompute(B128, points, wnafPoints, wnafPoints, t);

            PointAccum p = new PointAccum();
            F.copy(B_x, 0, p.x, 0);
            F.copy(B_y, 0, p.y, 0);
            F.one(p.z);
            F.copy(p.x, 0, p.u, 0);
            F.copy(p.y, 0, p.v, 0);

            int pointsIndex = wnafPoints * 2;
            PointExtended[] toothPowers = new PointExtended[PRECOMP_TEETH];
            for (int tooth = 0; tooth < PRECOMP_TEETH; ++tooth)
            {
                toothPowers[tooth] = new PointExtended();
            }

            PointExtended u = new PointExtended();
            for (int block = 0; block < PRECOMP_BLOCKS; ++block)
            {
                PointExtended sum = points[pointsIndex++] = new PointExtended();

                for (int tooth = 0; tooth < PRECOMP_TEETH; ++tooth)
                {
                    if (tooth == 0)
                    {
                        pointCopy(p, sum);
                    }
                    else
                    {
                        pointCopy(p, u);
                        pointAdd(sum, u, sum, t);
                    }

                    pointDouble(p);
                    pointCopy(p, toothPowers[tooth]);

                    if (block + tooth != PRECOMP_BLOCKS + PRECOMP_TEETH - 2)
                    {
                        for (int spacing = 1; spacing < PRECOMP_SPACING; ++spacing)
                        {
                            pointDouble(p);
                        }
                    }
                }

                F.negate(sum.x, sum.x);
                F.negate(sum.t, sum.t);

                for (int tooth = 0; tooth < (PRECOMP_TEETH - 1); ++tooth)
                {
                    int size = 1 << tooth;
                    for (int j = 0; j < size; ++j, ++pointsIndex)
                    {
                        points[pointsIndex] = new PointExtended();
                        pointAdd(points[pointsIndex - size], toothPowers[tooth], points[pointsIndex], t);
                    }
                }
            }
//            assert pointsIndex == totalPoints;

            // Set each z coordinate to 1/(2.z) to avoid calculating halves of x, y in the following code
            invertDoubleZs(points);

            PRECOMP_BASE_WNAF = new PointPrecomp[wnafPoints];
            for (int i = 0; i < wnafPoints; ++i)
            {
                PointExtended q = points[i];
                PointPrecomp r = PRECOMP_BASE_WNAF[i] = new PointPrecomp();

                // Calculate x/2 and y/2 (because the z value holds half the inverse; see above).
                F.mul(q.x, q.z, q.x);
                F.mul(q.y, q.z, q.y);

                // y/2 +/- x/2
                F.apm(q.y, q.x, r.ypx_h, r.ymx_h);

                // x/2 * y/2 * (4.d) == x.y.d
                F.mul(q.x, q.y, r.xyd);
                F.mul(r.xyd, C_d4, r.xyd);

                F.normalize(r.ymx_h);
                F.normalize(r.ypx_h);
                F.normalize(r.xyd);
            }

            PRECOMP_BASE128_WNAF = new PointPrecomp[wnafPoints];
            for (int i = 0; i < wnafPoints; ++i)
            {
                PointExtended q = points[wnafPoints + i];
                PointPrecomp r = PRECOMP_BASE128_WNAF[i] = new PointPrecomp();

                // Calculate x/2 and y/2 (because the z value holds half the inverse; see above).
                F.mul(q.x, q.z, q.x);
                F.mul(q.y, q.z, q.y);

                // y/2 +/- x/2
                F.apm(q.y, q.x, r.ypx_h, r.ymx_h);

                // x/2 * y/2 * (4.d) == x.y.d
                F.mul(q.x, q.y, r.xyd);
                F.mul(r.xyd, C_d4, r.xyd);

                F.normalize(r.ymx_h);
                F.normalize(r.ypx_h);
                F.normalize(r.xyd);
            }

            PRECOMP_BASE_COMB = F.createTable(combPoints * 3);
            PointPrecomp s = new PointPrecomp();
            int off = 0;
            for (int i = wnafPoints * 2; i < totalPoints; ++i)
            {
                PointExtended q = points[i];

                // Calculate x/2 and y/2 (because the z value holds half the inverse; see above).
                F.mul(q.x, q.z, q.x);
                F.mul(q.y, q.z, q.y);

                // y/2 +/- x/2
                F.apm(q.y, q.x, s.ypx_h, s.ymx_h);

                // x/2 * y/2 * (4.d) == x.y.d
                F.mul(q.x, q.y, s.xyd);
                F.mul(s.xyd, C_d4, s.xyd);

                F.normalize(s.ymx_h);
                F.normalize(s.ypx_h);
                F.normalize(s.xyd);

                F.copy(s.ymx_h, 0, PRECOMP_BASE_COMB, off);       off += F.SIZE;
                F.copy(s.ypx_h, 0, PRECOMP_BASE_COMB, off);       off += F.SIZE;
                F.copy(s.xyd  , 0, PRECOMP_BASE_COMB, off);       off += F.SIZE;
            }
//            assert off == PRECOMP_BASE_COMB.length;
        }
    }

    private static void pruneScalar(byte[] n, int nOff, byte[] r)
    {
        System.arraycopy(n, nOff, r, 0, SCALAR_BYTES);

        r[0] &= 0xF8;
        r[SCALAR_BYTES - 1] &= 0x7F;
        r[SCALAR_BYTES - 1] |= 0x40;
    }

    private static void scalarMult(byte[] k, PointAffine p, PointAccum r)
    {
        int[] n = new int[SCALAR_INTS];
        Scalar25519.decode(k, n);
        Scalar25519.toSignedDigits(256, n);

        PointPrecompZ q = new PointPrecompZ();
        PointTemp t = new PointTemp();
        int[] table = pointPrecomputeZ(p, 8, t);

        pointSetNeutral(r);

        int w = 63;
        for (;;)
        {
            pointLookupZ(n, w, table, q);
            pointAdd(q, r, t);

            if (--w < 0)
            {
                break;
            }

            for (int i = 0; i < 4; ++i)
            {
                pointDouble(r);
            }
        }
    }

    private static void scalarMultBase(byte[] k, PointAccum r)
    {
        // Equivalent (but much slower)
//        PointAffine p = new PointAffine();
//        F.copy(B_x, 0, p.x, 0);
//        F.copy(B_y, 0, p.y, 0);
//        scalarMult(k, p, r);

        precompute();

        int[] n = new int[SCALAR_INTS];
        Scalar25519.decode(k, n);
        Scalar25519.toSignedDigits(PRECOMP_RANGE, n);
        groupCombBits(n);

        PointPrecomp p = new PointPrecomp();
        PointTemp t = new PointTemp();

        pointSetNeutral(r);
        int resultSign = 0;

        int cOff = (PRECOMP_SPACING - 1) * PRECOMP_TEETH;
        for (;;)
        {
            for (int block = 0; block < PRECOMP_BLOCKS; ++block)
            {
                int w = n[block] >>> cOff;
                int sign = (w >>> (PRECOMP_TEETH - 1)) & 1;
                int abs = (w ^ -sign) & PRECOMP_MASK;

//                assert sign == 0 || sign == 1;
//                assert 0 <= abs && abs < PRECOMP_POINTS;

                pointLookup(block, abs, p);

                F.cnegate(resultSign ^ sign, r.x);
                F.cnegate(resultSign ^ sign, r.u);
                resultSign = sign;

                pointAdd(p, r, t);
            }

            if ((cOff -= PRECOMP_TEETH) < 0)
            {
                break;
            }

            pointDouble(r);
        }

        F.cnegate(resultSign, r.x);
        F.cnegate(resultSign, r.u);
    }

    private static void scalarMultBaseEncoded(byte[] k, byte[] r, int rOff)
    {
        PointAccum p = new PointAccum();
        scalarMultBase(k, p);
        if (0 == encodeResult(p, r, rOff))
        {
            throw new IllegalStateException();
        }
    }

    /**
     * NOTE: Only for use by X25519
     */
    public static void scalarMultBaseYZ(X25519.Friend friend, byte[] k, int kOff, int[] y, int[] z)
    {
        if (null == friend)
        {
            throw new NullPointerException("This method is only for use by X25519");
        }

        byte[] n = new byte[SCALAR_BYTES];
        pruneScalar(k, kOff, n);

        PointAccum p = new PointAccum();
        scalarMultBase(n, p);
        if (0 == checkPoint(p))
        {
            throw new IllegalStateException();
        }

        F.copy(p.y, 0, y, 0);
        F.copy(p.z, 0, z, 0);
    }

    private static void scalarMultOrderVar(PointAffine p, PointAccum r)
    {
        byte[] ws_p = new byte[253];

        // NOTE: WNAF_WIDTH_128 because of the special structure of the order
        Scalar25519.getOrderWnafVar(WNAF_WIDTH_128, ws_p);

        int count = 1 << (WNAF_WIDTH_128 - 2);
        PointPrecompZ[] tp = new PointPrecompZ[count];
        PointTemp t = new PointTemp();
        pointPrecomputeZ(p, tp, count, t);

        pointSetNeutral(r);

        for (int bit = 252;;)
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

            pointDouble(r);
        }
    }

    private static void scalarMultStraus128Var(int[] nb, int[] np, PointAffine p, int[] nq, PointAffine q, PointAccum r)
    {
//        assert nb.length == SCALAR_INTS;
//        assert nb[SCALAR_INTS - 1] >>> 29 == 0;
//        assert np.length == 4;
//        assert nq.length == 4;

        precompute();

        byte[] ws_b = new byte[256];
        byte[] ws_p = new byte[128];
        byte[] ws_q = new byte[128];

        Wnaf.getSignedVar(nb, WNAF_WIDTH_BASE, ws_b);
        Wnaf.getSignedVar(np, WNAF_WIDTH_128, ws_p);
        Wnaf.getSignedVar(nq, WNAF_WIDTH_128, ws_q);

        int count = 1 << (WNAF_WIDTH_128 - 2);
        PointPrecompZ[] tp = new PointPrecompZ[count];
        PointPrecompZ[] tq = new PointPrecompZ[count];
        PointTemp t = new PointTemp();
        pointPrecomputeZ(p, tp, count, t);
        pointPrecomputeZ(q, tq, count, t);

        pointSetNeutral(r);

        int bit = 128;
        while (--bit >= 0)
        {
            if ((ws_b[bit] | ws_b[128 + bit] | ws_p[bit] | ws_q[bit]) != 0)
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

            int wb128 = ws_b[128 + bit];
            if (wb128 != 0)
            {
                int index = (wb128 >> 1) ^ (wb128 >> 31);
                pointAddVar(wb128 < 0, PRECOMP_BASE128_WNAF[index], r, t);
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

            pointDouble(r);
        }

        // NOTE: Together with the final pointDouble of the loop, this clears the cofactor of 8
        pointDouble(r);
        pointDouble(r);
    }

    public static void sign(byte[] sk, int skOff, byte[] m, int mOff, int mLen, byte[] sig, int sigOff)
    {
        byte[] ctx = null;
        byte phflag = 0x00;

        implSign(sk, skOff, ctx, phflag, m, mOff, mLen, sig, sigOff);
    }

    public static void sign(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] m, int mOff, int mLen, byte[] sig,
        int sigOff)
    {
        byte[] ctx = null;
        byte phflag = 0x00;

        implSign(sk, skOff, pk, pkOff, ctx, phflag, m, mOff, mLen, sig, sigOff);
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

    public static void signPrehash(byte[] sk, int skOff, byte[] ctx, Digest ph, byte[] sig, int sigOff)
    {
        byte[] m = new byte[PREHASH_SIZE];
        if (PREHASH_SIZE != ph.doFinal(m, 0))
        {
            throw new IllegalArgumentException("ph");
        }

        byte phflag = 0x01;

        implSign(sk, skOff, ctx, phflag, m, 0, m.length, sig, sigOff);
    }

    public static void signPrehash(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] ctx, Digest ph, byte[] sig,
        int sigOff)
    {
        byte[] m = new byte[PREHASH_SIZE];
        if (PREHASH_SIZE != ph.doFinal(m, 0))
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

    public static boolean verify(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] m, int mOff, int mLen)
    {
        byte[] ctx = null;
        byte phflag = 0x00;

        return implVerify(sig, sigOff, pk, pkOff, ctx, phflag, m, mOff, mLen);
    }

    public static boolean verify(byte[] sig, int sigOff, PublicPoint publicPoint, byte[] m, int mOff, int mLen)
    {
        byte[] ctx = null;
        byte phflag = 0x00;

        return implVerify(sig, sigOff, publicPoint, ctx, phflag, m, mOff, mLen);
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

    public static boolean verifyPrehash(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] ctx, Digest ph)
    {
        byte[] m = new byte[PREHASH_SIZE];
        if (PREHASH_SIZE != ph.doFinal(m, 0))
        {
            throw new IllegalArgumentException("ph");
        }

        byte phflag = 0x01;

        return implVerify(sig, sigOff, pk, pkOff, ctx, phflag, m, 0, m.length);
    }

    public static boolean verifyPrehash(byte[] sig, int sigOff, PublicPoint publicPoint, byte[] ctx, Digest ph)
    {
        byte[] m = new byte[PREHASH_SIZE];
        if (PREHASH_SIZE != ph.doFinal(m, 0))
        {
            throw new IllegalArgumentException("ph");
        }

        byte phflag = 0x01;

        return implVerify(sig, sigOff, publicPoint, ctx, phflag, m, 0, m.length);
    }
}
