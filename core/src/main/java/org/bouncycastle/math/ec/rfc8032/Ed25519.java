package org.bouncycastle.math.ec.rfc8032;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.math.ec.rfc7748.X25519Field;
import org.bouncycastle.math.raw.Interleave;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat256;
import org.bouncycastle.util.Arrays;

public abstract class Ed25519
{
    // -x^2 + y^2 == 1 + 0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3 * x^2 * y^2

    public static final class Algorithm
    {
        public static final int Ed25519 = 0;
        public static final int Ed25519ctx = 1;
        public static final int Ed25519ph = 2;
    }

    private static class F extends X25519Field {};

    private static final long M08L = 0x000000FFL;
    private static final long M28L = 0x0FFFFFFFL;
    private static final long M32L = 0xFFFFFFFFL;

    private static final int POINT_BYTES = 32;
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
    private static final int[] L = new int[]{ 0x5CF5D3ED, 0x5812631A, 0xA2F79CD6, 0x14DEF9DE, 0x00000000, 0x00000000,
        0x00000000, 0x10000000 };

    private static final int L0 = 0xFCF5D3ED;   // L0:26/--
    private static final int L1 = 0x012631A6;   // L1:24/22
    private static final int L2 = 0x079CD658;   // L2:27/--
    private static final int L3 = 0xFF9DEA2F;   // L3:23/--
    private static final int L4 = 0x000014DF;   // L4:12/11

    private static final int[] B_x = new int[]{ 0x0325D51A, 0x018B5823, 0x007B2C95, 0x0304A92D, 0x00D2598E, 0x01D6DC5C,
        0x01388C7F, 0x013FEC0A, 0x029E6B72, 0x0042D26D };
    private static final int[] B_y = new int[]{ 0x02666658, 0x01999999, 0x00666666, 0x03333333, 0x00CCCCCC, 0x02666666,
        0x01999999, 0x00666666, 0x03333333, 0x00CCCCCC, };
    private static final int[] C_d = new int[]{ 0x035978A3, 0x02D37284, 0x018AB75E, 0x026A0A0E, 0x0000E014, 0x0379E898,
        0x01D01E5D, 0x01E738CC, 0x03715B7F, 0x00A406D9 };
    private static final int[] C_d2 = new int[]{ 0x02B2F159, 0x01A6E509, 0x01156EBD, 0x00D4141D, 0x0001C029, 0x02F3D130,
        0x03A03CBB, 0x01CE7198, 0x02E2B6FF, 0x00480DB3 };
    private static final int[] C_d4 = new int[]{ 0x0165E2B2, 0x034DCA13, 0x002ADD7A, 0x01A8283B, 0x00038052, 0x01E7A260,
        0x03407977, 0x019CE331, 0x01C56DFF, 0x00901B67 };

    private static final int WNAF_WIDTH_BASE = 7;

    private static final int PRECOMP_BLOCKS = 8;
    private static final int PRECOMP_TEETH = 4;
    private static final int PRECOMP_SPACING = 8;
    private static final int PRECOMP_POINTS = 1 << (PRECOMP_TEETH - 1);
    private static final int PRECOMP_MASK = PRECOMP_POINTS - 1;

    private static final Object precompLock = new Object();
    // TODO[ed25519] Convert to PointPrecomp
    private static PointExt[] precompBaseTable = null;
    private static int[] precompBase = null;

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

    private static class PointExt
    {
        int[] x = F.create();
        int[] y = F.create();
        int[] z = F.create();
        int[] t = F.create();
    }

    private static class PointPrecomp
    {
        int[] ypx_h = F.create();
        int[] ymx_h = F.create();
        int[] xyd = F.create();
    }

    private static byte[] calculateS(byte[] r, byte[] k, byte[] s)
    {
        int[] t = new int[SCALAR_INTS * 2];     decodeScalar(r, 0, t);
        int[] u = new int[SCALAR_INTS];         decodeScalar(k, 0, u);
        int[] v = new int[SCALAR_INTS];         decodeScalar(s, 0, v);

        Nat256.mulAddTo(u, v, t);

        byte[] result = new byte[SCALAR_BYTES * 2];
        for (int i = 0; i < t.length; ++i)
        {
            encode32(t[i], result, i * 4);
        }
        return reduceScalar(result);
    }

    private static boolean checkContextVar(byte[] ctx , byte phflag)
    {
        return ctx == null && phflag == 0x00 
            || ctx != null && ctx.length < 256;
    }

    private static int checkPoint(int[] x, int[] y)
    {
        int[] t = F.create();
        int[] u = F.create();
        int[] v = F.create();

        F.sqr(x, u);
        F.sqr(y, v);
        F.mul(u, v, t);
        F.sub(v, u, v);
        F.mul(t, C_d, t);
        F.addOne(t);
        F.sub(t, v, t);
        F.normalize(t);

        return F.isZero(t);
    }

    private static int checkPoint(int[] x, int[] y, int[] z)
    {
        int[] t = F.create();
        int[] u = F.create();
        int[] v = F.create();
        int[] w = F.create();

        F.sqr(x, u);
        F.sqr(y, v);
        F.sqr(z, w);
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

    private static boolean checkPointVar(byte[] p)
    {
        int[] t = new int[8];
        decode32(p, 0, t, 0, 8);
        t[7] &= 0x7FFFFFFF;
        return !Nat256.gte(t, P);
    }

    private static boolean checkScalarVar(byte[] s)
    {
        int[] n = new int[SCALAR_INTS];
        decodeScalar(s, 0, n);
        return !Nat256.gte(n, L);
    }

    private static Digest createDigest()
    {
        return new SHA512Digest();
    }

    public static Digest createPrehash()
    {
        return createDigest();
    }

    private static int decode24(byte[] bs, int off)
    {
        int n = bs[  off] & 0xFF;
        n |= (bs[++off] & 0xFF) << 8;
        n |= (bs[++off] & 0xFF) << 16;
        return n;
    }

    private static int decode32(byte[] bs, int off)
    {
        int n = bs[off] & 0xFF;
        n |= (bs[++off] & 0xFF) << 8;
        n |= (bs[++off] & 0xFF) << 16;
        n |=  bs[++off]         << 24;
        return n;
    }

    private static void decode32(byte[] bs, int bsOff, int[] n, int nOff, int nLen)
    {
        for (int i = 0; i < nLen; ++i)
        {
            n[nOff + i] = decode32(bs, bsOff + i * 4);
        }
    }

    private static boolean decodePointVar(byte[] p, int pOff, boolean negate, PointAffine r)
    {
        byte[] py = Arrays.copyOfRange(p, pOff, pOff + POINT_BYTES);
        if (!checkPointVar(py))
        {
            return false;
        }

        int x_0 = (py[POINT_BYTES - 1] & 0x80) >>> 7;
        py[POINT_BYTES - 1] &= 0x7F;

        F.decode(py, 0, r.y);

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
        }

        return true;
    }

    private static void decodeScalar(byte[] k, int kOff, int[] n)
    {
        decode32(k, kOff, n, 0, SCALAR_INTS);
    }

    private static void dom2(Digest d, byte phflag, byte[] ctx)
    {
        if (ctx != null)
        {
            int n = DOM2_PREFIX.length;
            byte[] t = new byte[n + 2 + ctx.length];
            System.arraycopy(DOM2_PREFIX, 0, t, 0, n);
            t[n] = phflag;
            t[n + 1] = (byte)ctx.length;
            System.arraycopy(ctx, 0, t, n + 2, ctx.length);

            d.update(t, 0, t.length);
        }
    }

    private static void encode24(int n, byte[] bs, int off)
    {
        bs[  off] = (byte)(n       );
        bs[++off] = (byte)(n >>>  8);
        bs[++off] = (byte)(n >>> 16);
    }

    private static void encode32(int n, byte[] bs, int off)
    {
        bs[  off] = (byte)(n       );
        bs[++off] = (byte)(n >>>  8);
        bs[++off] = (byte)(n >>> 16);
        bs[++off] = (byte)(n >>> 24);
    }

    private static void encode56(long n, byte[] bs, int off)
    {
        encode32((int)n, bs, off);
        encode24((int)(n >>> 32), bs, off + 4);
    }

    private static int encodePoint(PointAccum p, byte[] r, int rOff)
    {
        int[] x = F.create();
        int[] y = F.create();

        F.inv(p.z, y);
        F.mul(p.x, y, x);
        F.mul(p.y, y, y);
        F.normalize(x);
        F.normalize(y);

        int result = checkPoint(x, y);

        F.encode(y, r, rOff);
        r[rOff + POINT_BYTES - 1] |= ((x[0] & 1) << 7);

        return result;
    }

    public static void generatePrivateKey(SecureRandom random, byte[] k)
    {
        random.nextBytes(k);
    }

    public static void generatePublicKey(byte[] sk, int skOff, byte[] pk, int pkOff)
    {
        Digest d = createDigest();
        byte[] h = new byte[d.getDigestSize()];

        d.update(sk, skOff, SECRET_KEY_SIZE);
        d.doFinal(h, 0);

        byte[] s = new byte[SCALAR_BYTES];
        pruneScalar(h, 0, s);

        scalarMultBaseEncoded(s, pk, pkOff);
    }

    private static int getWindow4(int[] x, int n)
    {
        int w = n >>> 3, b = (n & 7) << 2;
        return (x[w] >>> b) & 15;
    }

    private static byte[] getWnafVar(int[] n, int width)
    {
//        assert n[SCALAR_INTS - 1] >>> 28 == 0;

        int[] t = new int[SCALAR_INTS * 2];
        {
            int tPos = t.length, c = 0;
            int i = SCALAR_INTS;
            while (--i >= 0)
            {
                int next = n[i];
                t[--tPos] = (next >>> 16) | (c << 16);
                t[--tPos] = c = next;
            }
        }

        byte[] ws = new byte[253];

        final int pow2 = 1 << width;
        final int mask = pow2 - 1;
        final int sign = pow2 >>> 1;

        int j = 0, carry = 0;
        for (int i = 0; i < t.length; ++i, j -= 16)
        {
            int word = t[i];
            while (j < 16)
            {
                int word16 = word >>> j;
                int bit = word16 & 1;

                if (bit == carry)
                {
                    ++j;
                    continue;
                }

                int digit = (word16 & mask) + carry;
                carry = digit & sign;
                digit -= (carry << 1);
                carry >>>= (width - 1);

                ws[(i << 4) + j] = (byte)digit;

                j += width;
            }
        }

//        assert carry == 0;

        return ws;
    }

    private static void implSign(Digest d, byte[] h, byte[] s, byte[] pk, int pkOff, byte[] ctx, byte phflag, byte[] m,
        int mOff, int mLen, byte[] sig, int sigOff)
    {
        dom2(d, phflag, ctx);
        d.update(h, SCALAR_BYTES, SCALAR_BYTES);
        d.update(m, mOff, mLen);
        d.doFinal(h, 0);

        byte[] r = reduceScalar(h);
        byte[] R = new byte[POINT_BYTES];
        scalarMultBaseEncoded(r, R, 0);

        dom2(d, phflag, ctx);
        d.update(R, 0, POINT_BYTES);
        d.update(pk, pkOff, POINT_BYTES);
        d.update(m, mOff, mLen);
        d.doFinal(h, 0);

        byte[] k = reduceScalar(h);
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
        byte[] h = new byte[d.getDigestSize()];

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
        byte[] h = new byte[d.getDigestSize()];

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

        byte[] R = Arrays.copyOfRange(sig, sigOff, sigOff + POINT_BYTES);
        byte[] S = Arrays.copyOfRange(sig, sigOff + POINT_BYTES, sigOff + SIGNATURE_SIZE);

        if (!checkPointVar(R))
        {
            return false;
        }
        if (!checkScalarVar(S))
        {
            return false;
        }

        PointAffine pA = new PointAffine();
        if (!decodePointVar(pk, pkOff, true, pA))
        {
            return false;
        }

        Digest d = createDigest();
        byte[] h = new byte[d.getDigestSize()];

        dom2(d, phflag, ctx);
        d.update(R, 0, POINT_BYTES);
        d.update(pk, pkOff, POINT_BYTES);
        d.update(m, mOff, mLen);
        d.doFinal(h, 0);

        byte[] k = reduceScalar(h);

        int[] nS = new int[SCALAR_INTS];
        decodeScalar(S, 0, nS);

        int[] nA = new int[SCALAR_INTS];
        decodeScalar(k, 0, nA);

        PointAccum pR = new PointAccum();
        scalarMultStrausVar(nS, nA, pA, pR);

        byte[] check = new byte[POINT_BYTES];
        return 0 != encodePoint(pR, check, 0) && Arrays.areEqual(check, R);
    }

    private static void pointAdd(PointExt p, PointAccum r)
    {
        int[] a = F.create();
        int[] b = F.create();
        int[] c = F.create();
        int[] d = F.create();
        int[] e = r.u;
        int[] f = F.create();
        int[] g = F.create();
        int[] h = r.v;

        F.apm(r.y, r.x, b, a);
        F.apm(p.y, p.x, d, c);
        F.mul(a, c, a);
        F.mul(b, d, b);
        F.mul(r.u, r.v, c);
        F.mul(c, p.t, c);
        F.mul(c, C_d2, c);
        F.mul(r.z, p.z, d);
        F.add(d, d, d);
        F.apm(b, a, h, e);
        F.apm(d, c, g, f);
        F.carry(g);
        F.mul(e, f, r.x);
        F.mul(g, h, r.y);
        F.mul(f, g, r.z);
    }

    private static void pointAdd(PointExt p, PointExt r)
    {
        int[] a = F.create();
        int[] b = F.create();
        int[] c = F.create();
        int[] d = F.create();
        int[] e = F.create();
        int[] f = F.create();
        int[] g = F.create();
        int[] h = F.create();

        F.apm(p.y, p.x, b, a);
        F.apm(r.y, r.x, d, c);
        F.mul(a, c, a);
        F.mul(b, d, b);
        F.mul(p.t, r.t, c);
        F.mul(c, C_d2, c);
        F.mul(p.z, r.z, d);
        F.add(d, d, d);
        F.apm(b, a, h, e);
        F.apm(d, c, g, f);
        F.carry(g);
        F.mul(e, f, r.x);
        F.mul(g, h, r.y);
        F.mul(f, g, r.z);
        F.mul(e, h, r.t);
    }

    private static void pointAddVar(boolean negate, PointExt p, PointAccum r)
    {
        int[] a = F.create();
        int[] b = F.create();
        int[] c = F.create();
        int[] d = F.create();
        int[] e = r.u;
        int[] f = F.create();
        int[] g = F.create();
        int[] h = r.v;

        int[] nc, nd, nf, ng;
        if (negate)
        {
            nc = d; nd = c; nf = g; ng = f;
        }
        else
        {
            nc = c; nd = d; nf = f; ng = g;
        }

        F.apm(r.y, r.x, b, a);
        F.apm(p.y, p.x, nd, nc);
        F.mul(a, c, a);
        F.mul(b, d, b);
        F.mul(r.u, r.v, c);
        F.mul(c, p.t, c);
        F.mul(c, C_d2, c);
        F.mul(r.z, p.z, d);
        F.add(d, d, d);
        F.apm(b, a, h, e);
        F.apm(d, c, ng, nf);
        F.carry(ng);
        F.mul(e, f, r.x);
        F.mul(g, h, r.y);
        F.mul(f, g, r.z);
    }

    private static void pointAddVar(boolean negate, PointExt p, PointExt q, PointExt r)
    {
        int[] a = F.create();
        int[] b = F.create();
        int[] c = F.create();
        int[] d = F.create();
        int[] e = F.create();
        int[] f = F.create();
        int[] g = F.create();
        int[] h = F.create();

        int[] nc, nd, nf, ng;
        if (negate)
        {
            nc = d; nd = c; nf = g; ng = f;
        }
        else
        {
            nc = c; nd = d; nf = f; ng = g;
        }

        F.apm(p.y, p.x, b, a);
        F.apm(q.y, q.x, nd, nc);
        F.mul(a, c, a);
        F.mul(b, d, b);
        F.mul(p.t, q.t, c);
        F.mul(c, C_d2, c);
        F.mul(p.z, q.z, d);
        F.add(d, d, d);
        F.apm(b, a, h, e);
        F.apm(d, c, ng, nf);
        F.carry(ng);
        F.mul(e, f, r.x);
        F.mul(g, h, r.y);
        F.mul(f, g, r.z);
        F.mul(e, h, r.t);
    }

    private static void pointAddPrecomp(PointPrecomp p, PointAccum r)
    {
        int[] a = F.create();
        int[] b = F.create();
        int[] c = F.create();
        int[] e = r.u;
        int[] f = F.create();
        int[] g = F.create();
        int[] h = r.v;

        F.apm(r.y, r.x, b, a);
        F.mul(a, p.ymx_h, a);
        F.mul(b, p.ypx_h, b);
        F.mul(r.u, r.v, c);
        F.mul(c, p.xyd, c);
        F.apm(b, a, h, e);
        F.apm(r.z, c, g, f);
        F.carry(g);
        F.mul(e, f, r.x);
        F.mul(g, h, r.y);
        F.mul(f, g, r.z);
    }

    private static PointExt pointCopy(PointAccum p)
    {
        PointExt r = new PointExt();
        F.copy(p.x, 0, r.x, 0);
        F.copy(p.y, 0, r.y, 0);
        F.copy(p.z, 0, r.z, 0);
        F.mul(p.u, p.v, r.t);
        return r;
    }

    private static PointExt pointCopy(PointAffine p)
    {
        PointExt r = new PointExt();
        F.copy(p.x, 0, r.x, 0);
        F.copy(p.y, 0, r.y, 0);
        pointExtendXY(r);
        return r;
    }

    private static PointExt pointCopy(PointExt p)
    {
        PointExt r = new PointExt();
        pointCopy(p, r);
        return r;
    }

    private static void pointCopy(PointAffine p, PointAccum r)
    {
        F.copy(p.x, 0, r.x, 0);
        F.copy(p.y, 0, r.y, 0);
        pointExtendXY(r);
    }

    private static void pointCopy(PointExt p, PointExt r)
    {
        F.copy(p.x, 0, r.x, 0);
        F.copy(p.y, 0, r.y, 0);
        F.copy(p.z, 0, r.z, 0);
        F.copy(p.t, 0, r.t, 0);
    }

    private static void pointDouble(PointAccum r)
    {
        int[] a = F.create();
        int[] b = F.create();
        int[] c = F.create();
        int[] e = r.u;
        int[] f = F.create();
        int[] g = F.create();
        int[] h = r.v;

        F.sqr(r.x, a);
        F.sqr(r.y, b);
        F.sqr(r.z, c);
        F.add(c, c, c);
        F.apm(a, b, h, g);
        F.add(r.x, r.y, e);
        F.sqr(e, e);
        F.sub(h, e, e);
        F.add(c, g, f);
        F.carry(f);
        F.mul(e, f, r.x);
        F.mul(g, h, r.y);
        F.mul(f, g, r.z);
    }

    private static void pointExtendXY(PointAccum p)
    {
        F.one(p.z);
        F.copy(p.x, 0, p.u, 0);
        F.copy(p.y, 0, p.v, 0);
    }

    private static void pointExtendXY(PointExt p)
    {
        F.one(p.z);
        F.mul(p.x, p.y, p.t);
    }

    private static void pointLookup(int block, int index, PointPrecomp p)
    {
//        assert 0 <= block && block < PRECOMP_BLOCKS;
//        assert 0 <= index && index < PRECOMP_POINTS;

        int off = block * PRECOMP_POINTS * 3 * F.SIZE;

        for (int i = 0; i < PRECOMP_POINTS; ++i)
        {
            int cond = ((i ^ index) - 1) >> 31;
            F.cmov(cond, precompBase, off, p.ypx_h, 0);     off += F.SIZE;
            F.cmov(cond, precompBase, off, p.ymx_h, 0);     off += F.SIZE;
            F.cmov(cond, precompBase, off, p.xyd,   0);     off += F.SIZE;
        }
    }

    private static void pointLookup(int[] x, int n, int[] table, PointExt r)
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
            F.cmov(cond, table, off, r.t, 0);       off += F.SIZE;
        }

        F.cnegate(sign, r.x);
        F.cnegate(sign, r.t);
    }

    private static void pointLookup(int[] table, int index, PointExt r)
    {
        int off = F.SIZE * 4 * index;

        F.copy(table, off, r.x, 0);     off += F.SIZE;
        F.copy(table, off, r.y, 0);     off += F.SIZE;
        F.copy(table, off, r.z, 0);     off += F.SIZE;
        F.copy(table, off, r.t, 0);
    }

    private static int[] pointPrecompute(PointAffine p, int count)
    {
//        assert count > 0;

        PointExt q = pointCopy(p);
        PointExt d = pointCopy(q);
        pointAdd(q, d);

        int[] table = F.createTable(count * 4);
        int off = 0;

        int i = 0;
        for (;;)
        {
            F.copy(q.x, 0, table, off);     off += F.SIZE;
            F.copy(q.y, 0, table, off);     off += F.SIZE;
            F.copy(q.z, 0, table, off);     off += F.SIZE;
            F.copy(q.t, 0, table, off);     off += F.SIZE;

            if (++i == count)
            {
                break;
            }

            pointAdd(d, q);
        }

        return table;
    }

    private static PointExt[] pointPrecomputeVar(PointExt p, int count)
    {
//        assert count > 0;

        PointExt d = new PointExt();
        pointAddVar(false, p, p, d);

        PointExt[] table = new PointExt[count];
        table[0] = pointCopy(p);
        for (int i = 1; i < count; ++i)
        {
            pointAddVar(false, table[i - 1], d, table[i] = new PointExt());
        }
        return table;
    }

    private static void pointSetNeutral(PointAccum p)
    {
        F.zero(p.x);
        F.one(p.y);
        F.one(p.z);
        F.zero(p.u);
        F.one(p.v);
    }

    private static void pointSetNeutral(PointExt p)
    {
        F.zero(p.x);
        F.one(p.y);
        F.one(p.z);
        F.zero(p.t);
    }

    public static void precompute()
    {
        synchronized (precompLock)
        {
            if (precompBase != null)
            {
                return;
            }

            // Precomputed table for the base point in verification ladder
            {
                PointExt b = new PointExt();
                F.copy(B_x, 0, b.x, 0);
                F.copy(B_y, 0, b.y, 0);
                pointExtendXY(b);

                precompBaseTable = pointPrecomputeVar(b, 1 << (WNAF_WIDTH_BASE - 2));
            }

            PointAccum p = new PointAccum();
            F.copy(B_x, 0, p.x, 0);
            F.copy(B_y, 0, p.y, 0);
            pointExtendXY(p);

            precompBase = F.createTable(PRECOMP_BLOCKS * PRECOMP_POINTS * 3);

            int off = 0;
            for (int b = 0; b < PRECOMP_BLOCKS; ++b)
            {
                PointExt[] ds = new PointExt[PRECOMP_TEETH];

                PointExt sum = new PointExt();
                pointSetNeutral(sum);

                for (int t = 0; t < PRECOMP_TEETH; ++t)
                {
                    PointExt q = pointCopy(p);
                    pointAddVar(true, sum, q, sum);
                    pointDouble(p);

                    ds[t] = pointCopy(p);

                    if (b + t != PRECOMP_BLOCKS + PRECOMP_TEETH - 2)
                    {
                        for (int s = 1; s < PRECOMP_SPACING; ++s)
                        {
                            pointDouble(p);
                        }
                    }
                }

                PointExt[] points = new PointExt[PRECOMP_POINTS];
                int k = 0;
                points[k++] = sum;

                for (int t = 0; t < (PRECOMP_TEETH - 1); ++t)
                {
                    int size = 1 << t;
                    for (int j = 0; j < size; ++j, ++k)
                    {
                        pointAddVar(false, points[k - size], ds[t], points[k] = new PointExt());
                    }
                }

//                assert k == PRECOMP_POINTS;

                int[] cs = F.createTable(PRECOMP_POINTS);

                // TODO[ed25519] A single batch inversion across all blocks?
                {
                    int[] u = F.create();
                    F.copy(points[0].z, 0, u, 0);
                    F.copy(u, 0, cs, 0);

                    int i = 0;
                    while (++i < PRECOMP_POINTS)
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
                        F.copy(t, 0, cs, j * F.SIZE);
                        F.mul(u, points[j].z, u);
                    }

                    F.copy(u, 0, cs, 0);
                }

                for (int i = 0; i < PRECOMP_POINTS; ++i)
                {
                    PointExt q = points[i];

                    int[] x = F.create();
                    int[] y = F.create();

//                    F.add(q.z, q.z, x);
//                    F.invVar(x, y);
                    F.copy(cs, i * F.SIZE, y, 0);

                    F.mul(q.x, y, x);
                    F.mul(q.y, y, y);

                    PointPrecomp r = new PointPrecomp();
                    F.apm(y, x, r.ypx_h, r.ymx_h);
                    F.mul(x, y, r.xyd);
                    F.mul(r.xyd, C_d4, r.xyd);

                    F.normalize(r.ypx_h);
                    F.normalize(r.ymx_h);
//                    F.normalize(r.xyd);

                    F.copy(r.ypx_h, 0, precompBase, off);       off += F.SIZE;
                    F.copy(r.ymx_h, 0, precompBase, off);       off += F.SIZE;
                    F.copy(r.xyd,   0, precompBase, off);       off += F.SIZE;
                }
            }

//            assert off == precompBase.length;
        }
    }

    private static void pruneScalar(byte[] n, int nOff, byte[] r)
    {
        System.arraycopy(n, nOff, r, 0, SCALAR_BYTES);

        r[0] &= 0xF8;
        r[SCALAR_BYTES - 1] &= 0x7F;
        r[SCALAR_BYTES - 1] |= 0x40;
    }

    private static byte[] reduceScalar(byte[] n)
    {
        long x00 =  decode32(n,  0)       & M32L;   // x00:32/--
        long x01 = (decode24(n,  4) << 4) & M32L;   // x01:28/--
        long x02 =  decode32(n,  7)       & M32L;   // x02:32/--
        long x03 = (decode24(n, 11) << 4) & M32L;   // x03:28/--
        long x04 =  decode32(n, 14)       & M32L;   // x04:32/--
        long x05 = (decode24(n, 18) << 4) & M32L;   // x05:28/--
        long x06 =  decode32(n, 21)       & M32L;   // x06:32/--
        long x07 = (decode24(n, 25) << 4) & M32L;   // x07:28/--
        long x08 =  decode32(n, 28)       & M32L;   // x08:32/--
        long x09 = (decode24(n, 32) << 4) & M32L;   // x09:28/--
        long x10 =  decode32(n, 35)       & M32L;   // x10:32/--
        long x11 = (decode24(n, 39) << 4) & M32L;   // x11:28/--
        long x12 =  decode32(n, 42)       & M32L;   // x12:32/--
        long x13 = (decode24(n, 46) << 4) & M32L;   // x13:28/--
        long x14 =  decode32(n, 49)       & M32L;   // x14:32/--
        long x15 = (decode24(n, 53) << 4) & M32L;   // x15:28/--
        long x16 =  decode32(n, 56)       & M32L;   // x16:32/--
        long x17 = (decode24(n, 60) << 4) & M32L;   // x17:28/--
        long x18 =  n[63]                 & M08L;   // x18:08/--
        long t;

//        x18 += (x17 >> 28); x17 &= M28L;
        x09 -= x18 * L0;                            // x09:34/28
        x10 -= x18 * L1;                            // x10:33/30
        x11 -= x18 * L2;                            // x11:35/28
        x12 -= x18 * L3;                            // x12:32/31
        x13 -= x18 * L4;                            // x13:28/21

        x17 += (x16 >> 28); x16 &= M28L;            // x17:28/--, x16:28/--
        x08 -= x17 * L0;                            // x08:54/32
        x09 -= x17 * L1;                            // x09:52/51
        x10 -= x17 * L2;                            // x10:55/34
        x11 -= x17 * L3;                            // x11:51/36
        x12 -= x17 * L4;                            // x12:41/--

//        x16 += (x15 >> 28); x15 &= M28L;
        x07 -= x16 * L0;                            // x07:54/28
        x08 -= x16 * L1;                            // x08:54/53
        x09 -= x16 * L2;                            // x09:55/53
        x10 -= x16 * L3;                            // x10:55/52
        x11 -= x16 * L4;                            // x11:51/41

        x15 += (x14 >> 28); x14 &= M28L;            // x15:28/--, x14:28/--
        x06 -= x15 * L0;                            // x06:54/32
        x07 -= x15 * L1;                            // x07:54/53
        x08 -= x15 * L2;                            // x08:56/--
        x09 -= x15 * L3;                            // x09:55/54
        x10 -= x15 * L4;                            // x10:55/53

//        x14 += (x13 >> 28); x13 &= M28L;
        x05 -= x14 * L0;                            // x05:54/28
        x06 -= x14 * L1;                            // x06:54/53
        x07 -= x14 * L2;                            // x07:56/--
        x08 -= x14 * L3;                            // x08:56/51
        x09 -= x14 * L4;                            // x09:56/--

        x13 += (x12 >> 28); x12 &= M28L;            // x13:28/22, x12:28/--
        x04 -= x13 * L0;                            // x04:54/49
        x05 -= x13 * L1;                            // x05:54/53
        x06 -= x13 * L2;                            // x06:56/--
        x07 -= x13 * L3;                            // x07:56/52
        x08 -= x13 * L4;                            // x08:56/52

        x12 += (x11 >> 28); x11 &= M28L;            // x12:28/24, x11:28/--
        x03 -= x12 * L0;                            // x03:54/49
        x04 -= x12 * L1;                            // x04:54/51
        x05 -= x12 * L2;                            // x05:56/--
        x06 -= x12 * L3;                            // x06:56/52
        x07 -= x12 * L4;                            // x07:56/53

        x11 += (x10 >> 28); x10 &= M28L;            // x11:29/--, x10:28/--
        x02 -= x11 * L0;                            // x02:55/32
        x03 -= x11 * L1;                            // x03:55/--
        x04 -= x11 * L2;                            // x04:56/55
        x05 -= x11 * L3;                            // x05:56/52
        x06 -= x11 * L4;                            // x06:56/53

        x10 += (x09 >> 28); x09 &= M28L;            // x10:29/--, x09:28/--
        x01 -= x10 * L0;                            // x01:55/28
        x02 -= x10 * L1;                            // x02:55/54
        x03 -= x10 * L2;                            // x03:56/55
        x04 -= x10 * L3;                            // x04:57/--
        x05 -= x10 * L4;                            // x05:56/53

        x08 += (x07 >> 28); x07 &= M28L;            // x08:56/53, x07:28/--
        x09 += (x08 >> 28); x08 &= M28L;            // x09:29/25, x08:28/--

        t    = x08 >>> 27;
        x09 += t;                                   // x09:29/26

        x00 -= x09 * L0;                            // x00:55/53
        x01 -= x09 * L1;                            // x01:55/54
        x02 -= x09 * L2;                            // x02:57/--
        x03 -= x09 * L3;                            // x03:57/--
        x04 -= x09 * L4;                            // x04:57/42

        x01 += (x00 >> 28); x00 &= M28L;
        x02 += (x01 >> 28); x01 &= M28L;
        x03 += (x02 >> 28); x02 &= M28L;
        x04 += (x03 >> 28); x03 &= M28L;
        x05 += (x04 >> 28); x04 &= M28L;
        x06 += (x05 >> 28); x05 &= M28L;
        x07 += (x06 >> 28); x06 &= M28L;
        x08 += (x07 >> 28); x07 &= M28L;
        x09  = (x08 >> 28); x08 &= M28L;

        x09 -= t;

//        assert x09 == 0L || x09 == -1L;

        x00 += x09 & L0;
        x01 += x09 & L1;
        x02 += x09 & L2;
        x03 += x09 & L3;
        x04 += x09 & L4;

        x01 += (x00 >> 28); x00 &= M28L;
        x02 += (x01 >> 28); x01 &= M28L;
        x03 += (x02 >> 28); x02 &= M28L;
        x04 += (x03 >> 28); x03 &= M28L;
        x05 += (x04 >> 28); x04 &= M28L;
        x06 += (x05 >> 28); x05 &= M28L;
        x07 += (x06 >> 28); x06 &= M28L;
        x08 += (x07 >> 28); x07 &= M28L;

        byte[] r = new byte[SCALAR_BYTES];
        encode56(x00 | (x01 << 28), r,  0);
        encode56(x02 | (x03 << 28), r,  7);
        encode56(x04 | (x05 << 28), r, 14);
        encode56(x06 | (x07 << 28), r, 21);
        encode32((int)x08,          r, 28);
        return r;
    }

    private static void scalarMult(byte[] k, PointAffine p, PointAccum r)
    {
        int[] n = new int[SCALAR_INTS];
        decodeScalar(k, 0, n);

//        assert 0 == (n[0] & 7);
//        assert 1 == n[SCALAR_INTS - 1] >>> 30;

        Nat.shiftDownBits(SCALAR_INTS, n, 3, 1);

        // Recode the scalar into signed-digit form
        {
            //int c1 =
            Nat.cadd(SCALAR_INTS, ~n[0] & 1, n, L, n);      //assert c1 == 0;
            //int c2 =           
            Nat.shiftDownBit(SCALAR_INTS, n, 0);            //assert c2 == (1 << 31);
        }

//        assert 1 == n[SCALAR_INTS - 1] >>> 28;

        int[] table = pointPrecompute(p, 8);
        PointExt q = new PointExt();

        // Replace first 4 doublings (2^4 * P) with 1 addition (P + 15 * P)
        pointCopy(p, r);
        pointLookup(table, 7, q);
        pointAdd(q, r);

        int w = 62;
        for (;;)
        {
            pointLookup(n, w, table, q);
            pointAdd(q, r);

            pointDouble(r);
            pointDouble(r);
            pointDouble(r);

            if (--w < 0)
            {
                break;
            }

            pointDouble(r);
        }
    }

    private static void scalarMultBase(byte[] k, PointAccum r)
    {
        precompute();

        int[] n = new int[SCALAR_INTS];
        decodeScalar(k, 0, n);

        // Recode the scalar into signed-digit form, then group comb bits in each block
        {
            //int c1 =
            Nat.cadd(SCALAR_INTS, ~n[0] & 1, n, L, n);      //assert c1 == 0;
            //int c2 =
            Nat.shiftDownBit(SCALAR_INTS, n, 1);            //assert c2 == (1 << 31);

            for (int i = 0; i < SCALAR_INTS; ++i)
            {
                n[i] = Interleave.shuffle2(n[i]);
            }
        }

        PointPrecomp p = new PointPrecomp();

        pointSetNeutral(r);

        int cOff = (PRECOMP_SPACING - 1) * PRECOMP_TEETH;
        for (;;)
        {
            for (int b = 0; b < PRECOMP_BLOCKS; ++b)
            {
                int w = n[b] >>> cOff;
                int sign = (w >>> (PRECOMP_TEETH - 1)) & 1;
                int abs = (w ^ -sign) & PRECOMP_MASK;

//                assert sign == 0 || sign == 1;
//                assert 0 <= abs && abs < PRECOMP_POINTS;

                pointLookup(b, abs, p);

                F.cswap(sign, p.ypx_h, p.ymx_h);
                F.cnegate(sign, p.xyd);

                pointAddPrecomp(p, r);
            }

            if ((cOff -= PRECOMP_TEETH) < 0)
            {
                break;
            }

            pointDouble(r);
        }
    }

    private static void scalarMultBaseEncoded(byte[] k, byte[] r, int rOff)
    {
        PointAccum p = new PointAccum();
        scalarMultBase(k, p);
        if (0 == encodePoint(p, r, rOff))
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
        if (0 == checkPoint(p.x, p.y, p.z))
        {
            throw new IllegalStateException();
        }
        F.copy(p.y, 0, y, 0);
        F.copy(p.z, 0, z, 0);
    }

    private static void scalarMultStrausVar(int[] nb, int[] np, PointAffine p, PointAccum r)
    {
        precompute();

        final int width = 5;

        byte[] ws_b = getWnafVar(nb, WNAF_WIDTH_BASE);
        byte[] ws_p = getWnafVar(np, width);

        PointExt[] tp = pointPrecomputeVar(pointCopy(p), 1 << (width - 2));

        pointSetNeutral(r);

        for (int bit = 252;;)
        {
            int wb = ws_b[bit];
            if (wb != 0)
            {
                int sign = wb >> 31;
                int index = (wb ^ sign) >>> 1;

                pointAddVar((sign != 0), precompBaseTable[index], r);
            }

            int wp = ws_p[bit];
            if (wp != 0)
            {
                int sign = wp >> 31;
                int index = (wp ^ sign) >>> 1;

                pointAddVar((sign != 0), tp[index], r);
            }

            if (--bit < 0)
            {
                break;
            }

            pointDouble(r);
        }
    }

    public static void sign(byte[] sk, int skOff, byte[] m, int mOff, int mLen, byte[] sig, int sigOff)
    {
        byte[] ctx = null;
        byte phflag = 0x00;

        implSign(sk, skOff, ctx, phflag, m, mOff, mLen, sig, sigOff);
    }

    public static void sign(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] m, int mOff, int mLen, byte[] sig, int sigOff)
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

    public static void sign(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] ctx, byte[] m, int mOff, int mLen, byte[] sig, int sigOff)
    {
        byte phflag = 0x00;

        implSign(sk, skOff, pk, pkOff, ctx, phflag, m, mOff, mLen, sig, sigOff);
    }

    public static void signPrehash(byte[] sk, int skOff, byte[] ctx, byte[] ph, int phOff, byte[] sig, int sigOff)
    {
        byte phflag = 0x01;

        implSign(sk, skOff, ctx, phflag, ph, phOff, PREHASH_SIZE, sig, sigOff);
    }

    public static void signPrehash(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] ctx, byte[] ph, int phOff, byte[] sig, int sigOff)
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

    public static void signPrehash(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] ctx, Digest ph, byte[] sig, int sigOff)
    {
        byte[] m = new byte[PREHASH_SIZE];
        if (PREHASH_SIZE != ph.doFinal(m, 0))
        {
            throw new IllegalArgumentException("ph");
        }

        byte phflag = 0x01;

        implSign(sk, skOff, pk, pkOff, ctx, phflag, m, 0, m.length, sig, sigOff);
    }

    public static boolean verify(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] m, int mOff, int mLen)
    {
        byte[] ctx = null;
        byte phflag = 0x00;

        return implVerify(sig, sigOff, pk, pkOff, ctx, phflag, m, mOff, mLen);
    }

    public static boolean verify(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] ctx, byte[] m, int mOff, int mLen)
    {
        byte phflag = 0x00;

        return implVerify(sig, sigOff, pk, pkOff, ctx, phflag, m, mOff, mLen);
    }

    public static boolean verifyPrehash(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] ctx, byte[] ph, int phOff)
    {
        byte phflag = 0x01;

        return implVerify(sig, sigOff, pk, pkOff, ctx, phflag, ph, phOff, PREHASH_SIZE);
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
}
