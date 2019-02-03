package org.bouncycastle.math.ec.rfc8032;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.math.ec.rfc7748.X448;
import org.bouncycastle.math.ec.rfc7748.X448Field;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public abstract class Ed448
{
    public static final class Algorithm
    {
        public static final int Ed448 = 0;
        public static final int Ed448ph = 1;
    }

    private static final long M26L = 0x03FFFFFFL;
    private static final long M28L = 0x0FFFFFFFL;
    private static final long M32L = 0xFFFFFFFFL;

    private static final int POINT_BYTES = 57;
    private static final int SCALAR_INTS = 14;
    private static final int SCALAR_BYTES = SCALAR_INTS * 4 + 1;

    public static final int PREHASH_SIZE = 64;
    public static final int PUBLIC_KEY_SIZE = POINT_BYTES;
    public static final int SECRET_KEY_SIZE = 57;
    public static final int SIGNATURE_SIZE = POINT_BYTES + SCALAR_BYTES;

    private static final byte[] DOM4_PREFIX = Strings.toByteArray("SigEd448");

    private static final int[] P = new int[] { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    private static final int[] L = new int[] { 0xAB5844F3, 0x2378C292, 0x8DC58F55, 0x216CC272, 0xAED63690, 0xC44EDB49, 0x7CCA23E9,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x3FFFFFFF };

    private static final int L_0 = 0x04A7BB0D;      // L_0:26/24
    private static final int L_1 = 0x0873D6D5;      // L_1:27/23
    private static final int L_2 = 0x0A70AADC;      // L_2:27/26
    private static final int L_3 = 0x03D8D723;      // L_3:26/--
    private static final int L_4 = 0x096FDE93;      // L_4:27/25
    private static final int L_5 = 0x0B65129C;      // L_5:27/26
    private static final int L_6 = 0x063BB124;      // L_6:27/--
    private static final int L_7 = 0x08335DC1;      // L_7:27/22

    private static final int L4_0 = 0x029EEC34;     // L4_0:25/24
    private static final int L4_1 = 0x01CF5B55;     // L4_1:25/--
    private static final int L4_2 = 0x09C2AB72;     // L4_2:27/25
    private static final int L4_3 = 0x0F635C8E;     // L4_3:28/--
    private static final int L4_4 = 0x05BF7A4C;     // L4_4:26/25
    private static final int L4_5 = 0x0D944A72;     // L4_5:28/--
    private static final int L4_6 = 0x08EEC492;     // L4_6:27/24
    private static final int L4_7 = 0x20CD7705;     // L4_7:29/24

    private static final int[] B_x = new int[] { 0x070CC05E, 0x026A82BC, 0x00938E26, 0x080E18B0, 0x0511433B, 0x0F72AB66, 0x0412AE1A,
        0x0A3D3A46, 0x0A6DE324, 0x00F1767E, 0x04657047, 0x036DA9E1, 0x05A622BF, 0x0ED221D1, 0x066BED0D, 0x04F1970C };
    private static final int[] B_y = new int[] { 0x0230FA14, 0x008795BF, 0x07C8AD98, 0x0132C4ED, 0x09C4FDBD, 0x01CE67C3, 0x073AD3FF,
        0x005A0C2D, 0x07789C1E, 0x0A398408, 0x0A73736C, 0x0C7624BE, 0x003756C9, 0x02488762, 0x016EB6BC, 0x0693F467 };
    private static final int C_d = -39081;

    private static final int WNAF_WIDTH_BASE = 7;

    private static final int PRECOMP_BLOCKS = 5;
    private static final int PRECOMP_TEETH = 5;
    private static final int PRECOMP_SPACING = 18;
    private static final int PRECOMP_POINTS = 1 << (PRECOMP_TEETH - 1);
    private static final int PRECOMP_MASK = PRECOMP_POINTS - 1;

    private static Object precompLock = new Object();
    // TODO[ed448] Convert to PointPrecomp
    private static PointExt[] precompBaseTable = null;
    private static int[] precompBase = null;

    private static class PointExt
    {
        int[] x = X448Field.create();
        int[] y = X448Field.create();
        int[] z = X448Field.create();
    }

    private static class PointPrecomp
    {
        int[] x = X448Field.create();
        int[] y = X448Field.create();
    }

    private static byte[] calculateS(byte[] r, byte[] k, byte[] s)
    {
        int[] t = new int[SCALAR_INTS * 2];     decodeScalar(r, 0, t);
        int[] u = new int[SCALAR_INTS];         decodeScalar(k, 0, u);
        int[] v = new int[SCALAR_INTS];         decodeScalar(s, 0, v);

        Nat.mulAddTo(14, u, v, t);

        byte[] result = new byte[SCALAR_BYTES * 2];
        for (int i = 0; i < t.length; ++i)
        {
            encode32(t[i], result, i * 4);
        }
        return reduceScalar(result);
    }

    private static boolean checkContextVar(byte[] ctx)
    {
        return ctx != null && ctx.length < 256;
    }

    private static boolean checkPointVar(byte[] p)
    {
        if ((p[POINT_BYTES - 1] & 0x7F) != 0x00)
        {
            return false;
        }

        int[] t = new int[14];
        decode32(p, 0, t, 0, 14);
        return !Nat.gte(14, t, P);
    }

    private static boolean checkScalarVar(byte[] s)
    {
        if (s[SCALAR_BYTES - 1] != 0x00)
        {
            return false;
        }

        int[] n = new int[SCALAR_INTS];
        decodeScalar(s, 0, n);
        return !Nat.gte(SCALAR_INTS, n, L);
    }

    public static Xof createPrehash()
    {
        return createXof();
    }

    private static Xof createXof()
    {
        return new SHAKEDigest(256);
    }

    private static int decode16(byte[] bs, int off)
    {
        int n = bs[off] & 0xFF;
        n |= (bs[++off] & 0xFF) << 8;
        return n;
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

    private static boolean decodePointVar(byte[] p, int pOff, boolean negate, PointExt r)
    {
        byte[] py = Arrays.copyOfRange(p, pOff, pOff + POINT_BYTES);
        if (!checkPointVar(py))
        {
            return false;
        }

        int x_0 = (py[POINT_BYTES - 1] & 0x80) >>> 7;
        py[POINT_BYTES - 1] &= 0x7F;

        X448Field.decode(py, 0, r.y);

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

        if (negate ^ (x_0 != (r.x[0] & 1)))
        {
            X448Field.negate(r.x, r.x);
        }

        pointExtendXY(r);
        return true;
    }

    private static void decodeScalar(byte[] k, int kOff, int[] n)
    {
//        assert k[kOff + SCALAR_BYTES - 1] == 0x00;

        decode32(k, kOff, n, 0, SCALAR_INTS);
    }

    private static void dom4(Xof d, byte x, byte[] y)
    {
        d.update(DOM4_PREFIX, 0, DOM4_PREFIX.length);
        d.update(x);
        d.update((byte)y.length);
        d.update(y, 0, y.length);
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

    private static void encodePoint(PointExt p, byte[] r, int rOff)
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

    public static void generatePrivateKey(SecureRandom random, byte[] k)
    {
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

    private static byte[] getWNAF(int[] n, int width)
    {
//        assert n[SCALAR_INTS - 1] >>> 31 == 0;

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

        byte[] ws = new byte[448];

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

    private static void implSign(Xof d, byte[] h, byte[] s, byte[] pk, int pkOff, byte[] ctx, byte phflag,
        byte[] m, int mOff, int mLen, byte[] sig, int sigOff)
    {
        dom4(d, phflag, ctx);
        d.update(h, SCALAR_BYTES, SCALAR_BYTES);
        d.update(m, mOff, mLen);
        d.doFinal(h, 0, h.length);

        byte[] r = reduceScalar(h);
        byte[] R = new byte[POINT_BYTES];
        scalarMultBaseEncoded(r, R, 0);

        dom4(d, phflag, ctx);
        d.update(R, 0, POINT_BYTES);
        d.update(pk, pkOff, POINT_BYTES);
        d.update(m, mOff, mLen);
        d.doFinal(h, 0, h.length);

        byte[] k = reduceScalar(h);
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

        PointExt pA = new PointExt();
        if (!decodePointVar(pk, pkOff, true, pA))
        {
            return false;
        }

        Xof d = createXof();
        byte[] h = new byte[SCALAR_BYTES * 2];

        dom4(d, phflag, ctx);
        d.update(R, 0, POINT_BYTES);
        d.update(pk, pkOff, POINT_BYTES);
        d.update(m, mOff, mLen);
        d.doFinal(h, 0, h.length);

        byte[] k = reduceScalar(h);

        int[] nS = new int[SCALAR_INTS];
        decodeScalar(S, 0, nS);

        int[] nA = new int[SCALAR_INTS];
        decodeScalar(k, 0, nA);

        PointExt pR = new PointExt();
        scalarMultStraussVar(nS, nA, pA, pR);

        byte[] check = new byte[POINT_BYTES];
        encodePoint(pR, check, 0);

        return Arrays.areEqual(check, R);
    }

    private static void pointAddVar(boolean negate, PointExt p, PointExt r)
    {
        int[] A = X448Field.create();
        int[] B = X448Field.create();
        int[] C = X448Field.create();
        int[] D = X448Field.create();
        int[] E = X448Field.create();
        int[] F = X448Field.create();
        int[] G = X448Field.create();
        int[] H = X448Field.create();

        int[] b, e, f, g;
        if (negate)
        {
            b = E; e = B; f = G; g = F;
            X448Field.sub(p.y, p.x, H);
        }
        else
        {
            b = B; e = E; f = F; g = G;
            X448Field.add(p.y, p.x, H);
        }

        X448Field.mul(p.z, r.z, A);
        X448Field.sqr(A, B);
        X448Field.mul(p.x, r.x, C);
        X448Field.mul(p.y, r.y, D);
        X448Field.mul(C, D, E);
        X448Field.mul(E, -C_d, E);
//        X448Field.apm(B, E, F, G);
        X448Field.add(B, E, f);
        X448Field.sub(B, E, g);
        X448Field.add(r.x, r.y, E);
        X448Field.mul(H, E, H);
//        X448Field.apm(D, C, B, E);
        X448Field.add(D, C, b);
        X448Field.sub(D, C, e);
        X448Field.carry(b);
        X448Field.sub(H, B, H);
        X448Field.mul(H, A, H);
        X448Field.mul(E, A, E);
        X448Field.mul(F, H, r.x);
        X448Field.mul(E, G, r.y);
        X448Field.mul(F, G, r.z);
    }

    private static void pointAddPrecomp(PointPrecomp p, PointExt r)
    {
        int[] B = X448Field.create();
        int[] C = X448Field.create();
        int[] D = X448Field.create();
        int[] E = X448Field.create();
        int[] F = X448Field.create();
        int[] G = X448Field.create();
        int[] H = X448Field.create();

        X448Field.sqr(r.z, B);
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
        X448Field.mul(H, r.z, H);
        X448Field.mul(E, r.z, E);
        X448Field.mul(F, H, r.x);
        X448Field.mul(E, G, r.y);
        X448Field.mul(F, G, r.z);
    }

    private static PointExt pointCopy(PointExt p)
    {
        PointExt r = new PointExt();
        X448Field.copy(p.x, 0, r.x, 0);
        X448Field.copy(p.y, 0, r.y, 0);
        X448Field.copy(p.z, 0, r.z, 0);
        return r;
    }

    private static void pointDouble(PointExt r)
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

    private static void pointExtendXY(PointExt p)
    {
        X448Field.one(p.z);
    }

    private static void pointLookup(int block, int index, PointPrecomp p)
    {
//        assert 0 <= block && block < PRECOMP_BLOCKS;
//        assert 0 <= index && index < PRECOMP_POINTS;

        int off = block * PRECOMP_POINTS * 2 * X448Field.SIZE;

        for (int i = 0; i < PRECOMP_POINTS; ++i)
        {
            int mask = ((i ^ index) - 1) >> 31;
            Nat.cmov(X448Field.SIZE, mask, precompBase, off, p.x, 0);   off += X448Field.SIZE;
            Nat.cmov(X448Field.SIZE, mask, precompBase, off, p.y, 0);   off += X448Field.SIZE;
        }
    }

    private static PointExt[] pointPrecompVar(PointExt p, int count)
    {
//        assert count > 0;

        PointExt d = pointCopy(p);
        pointDouble(d);

        PointExt[] table = new PointExt[count];
        table[0] = pointCopy(p);
        for (int i = 1; i < count; ++i)
        {
            table[i] = pointCopy(table[i - 1]);
            pointAddVar(false, d, table[i]);
        }
        return table;
    }

    private static void pointSetNeutral(PointExt p)
    {
        X448Field.zero(p.x);
        X448Field.one(p.y);
        X448Field.one(p.z);
    }

    public static void precompute()
    {
        synchronized (precompLock)
        {
            if (precompBase != null)
            {
                return;
            }

            PointExt p = new PointExt();
            X448Field.copy(B_x, 0, p.x, 0);
            X448Field.copy(B_y, 0, p.y, 0);
            pointExtendXY(p);

            precompBaseTable = pointPrecompVar(p, 1 << (WNAF_WIDTH_BASE - 2));

            precompBase = new int[PRECOMP_BLOCKS * PRECOMP_POINTS * 2 * X448Field.SIZE];

            int off = 0;
            for (int b = 0; b < PRECOMP_BLOCKS; ++b)
            {
                PointExt[] ds = new PointExt[PRECOMP_TEETH];

                PointExt sum = new PointExt();
                pointSetNeutral(sum);

                for (int t = 0; t < PRECOMP_TEETH; ++t)
                {
                    pointAddVar(true, p, sum);
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
                        points[k] = pointCopy(points[k - size]);
                        pointAddVar(false, ds[t], points[k]);
                    }
                }

//                assert k == PRECOMP_POINTS;

                for (int i = 0; i < PRECOMP_POINTS; ++i)
                {
                    PointExt q = points[i];
                    // TODO[ed448] Batch inversion
                    X448Field.inv(q.z, q.z);
                    X448Field.mul(q.x, q.z, q.x);
                    X448Field.mul(q.y, q.z, q.y);

//                    X448Field.normalize(q.x);
//                    X448Field.normalize(q.y);

                    X448Field.copy(q.x, 0, precompBase, off);   off += X448Field.SIZE;
                    X448Field.copy(q.y, 0, precompBase, off);   off += X448Field.SIZE;
                }
            }

//            assert off == precompBase.length;
        }
    }

    private static void pruneScalar(byte[] n, int nOff, byte[] r)
    {
        System.arraycopy(n, nOff, r, 0, SCALAR_BYTES - 1);

        r[0] &= 0xFC;
        r[SCALAR_BYTES - 2] |= 0x80;
        r[SCALAR_BYTES - 1]  = 0x00;
    }

    private static byte[] reduceScalar(byte[] n)
    {
        long x00 =  decode32(n,   0)       & M32L;  // x00:32/--
        long x01 = (decode24(n,   4) << 4) & M32L;  // x01:28/--
        long x02 =  decode32(n,   7)       & M32L;  // x02:32/--
        long x03 = (decode24(n,  11) << 4) & M32L;  // x03:28/--
        long x04 =  decode32(n,  14)       & M32L;  // x04:32/--
        long x05 = (decode24(n,  18) << 4) & M32L;  // x05:28/--
        long x06 =  decode32(n,  21)       & M32L;  // x06:32/--
        long x07 = (decode24(n,  25) << 4) & M32L;  // x07:28/--
        long x08 =  decode32(n,  28)       & M32L;  // x08:32/--
        long x09 = (decode24(n,  32) << 4) & M32L;  // x09:28/--
        long x10 =  decode32(n,  35)       & M32L;  // x10:32/--
        long x11 = (decode24(n,  39) << 4) & M32L;  // x11:28/--
        long x12 =  decode32(n,  42)       & M32L;  // x12:32/--
        long x13 = (decode24(n,  46) << 4) & M32L;  // x13:28/--
        long x14 =  decode32(n,  49)       & M32L;  // x14:32/--
        long x15 = (decode24(n,  53) << 4) & M32L;  // x15:28/--
        long x16 =  decode32(n,  56)       & M32L;  // x16:32/--
        long x17 = (decode24(n,  60) << 4) & M32L;  // x17:28/--
        long x18 =  decode32(n,  63)       & M32L;  // x18:32/--
        long x19 = (decode24(n,  67) << 4) & M32L;  // x19:28/--
        long x20 =  decode32(n,  70)       & M32L;  // x20:32/--
        long x21 = (decode24(n,  74) << 4) & M32L;  // x21:28/--
        long x22 =  decode32(n,  77)       & M32L;  // x22:32/--
        long x23 = (decode24(n,  81) << 4) & M32L;  // x23:28/--
        long x24 =  decode32(n,  84)       & M32L;  // x24:32/--
        long x25 = (decode24(n,  88) << 4) & M32L;  // x25:28/--
        long x26 =  decode32(n,  91)       & M32L;  // x26:32/--
        long x27 = (decode24(n,  95) << 4) & M32L;  // x27:28/--
        long x28 =  decode32(n,  98)       & M32L;  // x28:32/--
        long x29 = (decode24(n, 102) << 4) & M32L;  // x29:28/--
        long x30 =  decode32(n, 105)       & M32L;  // x30:32/--
        long x31 = (decode24(n, 109) << 4) & M32L;  // x31:28/--
        long x32 =  decode16(n, 112)       & M32L;  // x32:16/--

//        x32 += (x31 >>> 28); x31 &= M28L;
        x16 += x32 * L4_0;                          // x16:42/--
        x17 += x32 * L4_1;                          // x17:41/28
        x18 += x32 * L4_2;                          // x18:43/42
        x19 += x32 * L4_3;                          // x19:44/28
        x20 += x32 * L4_4;                          // x20:43/--
        x21 += x32 * L4_5;                          // x21:44/28
        x22 += x32 * L4_6;                          // x22:43/41
        x23 += x32 * L4_7;                          // x23:45/41

        x31 += (x30 >>> 28); x30 &= M28L;           // x31:28/--, x30:28/--
        x15 += x31 * L4_0;                          // x15:54/--
        x16 += x31 * L4_1;                          // x16:53/42
        x17 += x31 * L4_2;                          // x17:55/54
        x18 += x31 * L4_3;                          // x18:56/44
        x19 += x31 * L4_4;                          // x19:55/--
        x20 += x31 * L4_5;                          // x20:56/43
        x21 += x31 * L4_6;                          // x21:55/53
        x22 += x31 * L4_7;                          // x22:57/53

//        x30 += (x29 >>> 28); x29 &= M28L;
        x14 += x30 * L4_0;                          // x14:54/--
        x15 += x30 * L4_1;                          // x15:54/53
        x16 += x30 * L4_2;                          // x16:56/--
        x17 += x30 * L4_3;                          // x17:57/--
        x18 += x30 * L4_4;                          // x18:56/55
        x19 += x30 * L4_5;                          // x19:56/55
        x20 += x30 * L4_6;                          // x20:57/--
        x21 += x30 * L4_7;                          // x21:57/56

        x29 += (x28 >>> 28); x28 &= M28L;           // x29:28/--, x28:28/--
        x13 += x29 * L4_0;                          // x13:54/--
        x14 += x29 * L4_1;                          // x14:54/53
        x15 += x29 * L4_2;                          // x15:56/--
        x16 += x29 * L4_3;                          // x16:57/--
        x17 += x29 * L4_4;                          // x17:57/55
        x18 += x29 * L4_5;                          // x18:57/55
        x19 += x29 * L4_6;                          // x19:57/52
        x20 += x29 * L4_7;                          // x20:58/52

//        x28 += (x27 >>> 28); x27 &= M28L;
        x12 += x28 * L4_0;                          // x12:54/--
        x13 += x28 * L4_1;                          // x13:54/53
        x14 += x28 * L4_2;                          // x14:56/--
        x15 += x28 * L4_3;                          // x15:57/--
        x16 += x28 * L4_4;                          // x16:57/55
        x17 += x28 * L4_5;                          // x17:58/--
        x18 += x28 * L4_6;                          // x18:58/--
        x19 += x28 * L4_7;                          // x19:58/53

        x27 += (x26 >>> 28); x26 &= M28L;           // x27:28/--, x26:28/--
        x11 += x27 * L4_0;                          // x11:54/--
        x12 += x27 * L4_1;                          // x12:54/53
        x13 += x27 * L4_2;                          // x13:56/--
        x14 += x27 * L4_3;                          // x14:57/--
        x15 += x27 * L4_4;                          // x15:57/55
        x16 += x27 * L4_5;                          // x16:58/--
        x17 += x27 * L4_6;                          // x17:58/56
        x18 += x27 * L4_7;                          // x18:59/--

//        x26 += (x25 >>> 28); x25 &= M28L;
        x10 += x26 * L4_0;                          // x10:54/--
        x11 += x26 * L4_1;                          // x11:54/53
        x12 += x26 * L4_2;                          // x12:56/--
        x13 += x26 * L4_3;                          // x13:57/--
        x14 += x26 * L4_4;                          // x14:57/55
        x15 += x26 * L4_5;                          // x15:58/--
        x16 += x26 * L4_6;                          // x16:58/56
        x17 += x26 * L4_7;                          // x17:59/--

        x25 += (x24 >>> 28); x24 &= M28L;           // x25:28/--, x24:28/--
        x09 += x25 * L4_0;                          // x09:54/--
        x10 += x25 * L4_1;                          // x10:54/53
        x11 += x25 * L4_2;                          // x11:56/--
        x12 += x25 * L4_3;                          // x12:57/--
        x13 += x25 * L4_4;                          // x13:57/55
        x14 += x25 * L4_5;                          // x14:58/--
        x15 += x25 * L4_6;                          // x15:58/56
        x16 += x25 * L4_7;                          // x16:59/--

        x21 += (x20 >>> 28); x20 &= M28L;           // x21:58/--, x20:28/--
        x22 += (x21 >>> 28); x21 &= M28L;           // x22:57/54, x21:28/--
        x23 += (x22 >>> 28); x22 &= M28L;           // x23:45/42, x22:28/--
        x24 += (x23 >>> 28); x23 &= M28L;           // x24:28/18, x23:28/--

        x08 += x24 * L4_0;                          // x08:54/--
        x09 += x24 * L4_1;                          // x09:55/--
        x10 += x24 * L4_2;                          // x10:56/46
        x11 += x24 * L4_3;                          // x11:57/46
        x12 += x24 * L4_4;                          // x12:57/55
        x13 += x24 * L4_5;                          // x13:58/--
        x14 += x24 * L4_6;                          // x14:58/56
        x15 += x24 * L4_7;                          // x15:59/--

        x07 += x23 * L4_0;                          // x07:54/--
        x08 += x23 * L4_1;                          // x08:54/53
        x09 += x23 * L4_2;                          // x09:56/53
        x10 += x23 * L4_3;                          // x10:57/46
        x11 += x23 * L4_4;                          // x11:57/55
        x12 += x23 * L4_5;                          // x12:58/--
        x13 += x23 * L4_6;                          // x13:58/56
        x14 += x23 * L4_7;                          // x14:59/--

        x06 += x22 * L4_0;                          // x06:54/--
        x07 += x22 * L4_1;                          // x07:54/53
        x08 += x22 * L4_2;                          // x08:56/--
        x09 += x22 * L4_3;                          // x09:57/53
        x10 += x22 * L4_4;                          // x10:57/55
        x11 += x22 * L4_5;                          // x11:58/--
        x12 += x22 * L4_6;                          // x12:58/56
        x13 += x22 * L4_7;                          // x13:59/--

        x18 += (x17 >>> 28); x17 &= M28L;           // x18:59/31, x17:28/--
        x19 += (x18 >>> 28); x18 &= M28L;           // x19:58/54, x18:28/--
        x20 += (x19 >>> 28); x19 &= M28L;           // x20:30/29, x19:28/--
        x21 += (x20 >>> 28); x20 &= M28L;           // x21:28/03, x20:28/--

        x05 += x21 * L4_0;                          // x05:54/--
        x06 += x21 * L4_1;                          // x06:55/--
        x07 += x21 * L4_2;                          // x07:56/31
        x08 += x21 * L4_3;                          // x08:57/31
        x09 += x21 * L4_4;                          // x09:57/56
        x10 += x21 * L4_5;                          // x10:58/--
        x11 += x21 * L4_6;                          // x11:58/56
        x12 += x21 * L4_7;                          // x12:59/--

        x04 += x20 * L4_0;                          // x04:54/--
        x05 += x20 * L4_1;                          // x05:54/53
        x06 += x20 * L4_2;                          // x06:56/53
        x07 += x20 * L4_3;                          // x07:57/31
        x08 += x20 * L4_4;                          // x08:57/55
        x09 += x20 * L4_5;                          // x09:58/--
        x10 += x20 * L4_6;                          // x10:58/56
        x11 += x20 * L4_7;                          // x11:59/--

        x03 += x19 * L4_0;                          // x03:54/--
        x04 += x19 * L4_1;                          // x04:54/53
        x05 += x19 * L4_2;                          // x05:56/--
        x06 += x19 * L4_3;                          // x06:57/53
        x07 += x19 * L4_4;                          // x07:57/55
        x08 += x19 * L4_5;                          // x08:58/--
        x09 += x19 * L4_6;                          // x09:58/56
        x10 += x19 * L4_7;                          // x10:59/--

        x15 += (x14 >>> 28); x14 &= M28L;           // x15:59/31, x14:28/--
        x16 += (x15 >>> 28); x15 &= M28L;           // x16:59/32, x15:28/--
        x17 += (x16 >>> 28); x16 &= M28L;           // x17:31/29, x16:28/--
        x18 += (x17 >>> 28); x17 &= M28L;           // x18:28/04, x17:28/--

        x02 += x18 * L4_0;                          // x02:54/--
        x03 += x18 * L4_1;                          // x03:55/--
        x04 += x18 * L4_2;                          // x04:56/32
        x05 += x18 * L4_3;                          // x05:57/32
        x06 += x18 * L4_4;                          // x06:57/56
        x07 += x18 * L4_5;                          // x07:58/--
        x08 += x18 * L4_6;                          // x08:58/56
        x09 += x18 * L4_7;                          // x09:59/--

        x01 += x17 * L4_0;                          // x01:54/--
        x02 += x17 * L4_1;                          // x02:54/53
        x03 += x17 * L4_2;                          // x03:56/53
        x04 += x17 * L4_3;                          // x04:57/32
        x05 += x17 * L4_4;                          // x05:57/55
        x06 += x17 * L4_5;                          // x06:58/--
        x07 += x17 * L4_6;                          // x07:58/56
        x08 += x17 * L4_7;                          // x08:59/--

        x16 *= 4;
        x16 += (x15 >>> 26); x15 &= M26L;
        x16 += 1;                                   // x16:30/01

        x00 += x16 * L_0;
        x01 += x16 * L_1;
        x02 += x16 * L_2;
        x03 += x16 * L_3;
        x04 += x16 * L_4;
        x05 += x16 * L_5;
        x06 += x16 * L_6;
        x07 += x16 * L_7;

        x01 += (x00 >>> 28); x00 &= M28L;
        x02 += (x01 >>> 28); x01 &= M28L;
        x03 += (x02 >>> 28); x02 &= M28L;
        x04 += (x03 >>> 28); x03 &= M28L;
        x05 += (x04 >>> 28); x04 &= M28L;
        x06 += (x05 >>> 28); x05 &= M28L;
        x07 += (x06 >>> 28); x06 &= M28L;
        x08 += (x07 >>> 28); x07 &= M28L;
        x09 += (x08 >>> 28); x08 &= M28L;
        x10 += (x09 >>> 28); x09 &= M28L;
        x11 += (x10 >>> 28); x10 &= M28L;
        x12 += (x11 >>> 28); x11 &= M28L;
        x13 += (x12 >>> 28); x12 &= M28L;
        x14 += (x13 >>> 28); x13 &= M28L;
        x15 += (x14 >>> 28); x14 &= M28L;
        x16  = (x15 >>> 26); x15 &= M26L;

        x16 -= 1;

//        assert x16 == 0L || x16 == -1L;

        x00 -= x16 & L_0;
        x01 -= x16 & L_1;
        x02 -= x16 & L_2;
        x03 -= x16 & L_3;
        x04 -= x16 & L_4;
        x05 -= x16 & L_5;
        x06 -= x16 & L_6;
        x07 -= x16 & L_7;

        x01 += (x00 >> 28); x00 &= M28L;
        x02 += (x01 >> 28); x01 &= M28L;
        x03 += (x02 >> 28); x02 &= M28L;
        x04 += (x03 >> 28); x03 &= M28L;
        x05 += (x04 >> 28); x04 &= M28L;
        x06 += (x05 >> 28); x05 &= M28L;
        x07 += (x06 >> 28); x06 &= M28L;
        x08 += (x07 >> 28); x07 &= M28L;
        x09 += (x08 >> 28); x08 &= M28L;
        x10 += (x09 >> 28); x09 &= M28L;
        x11 += (x10 >> 28); x10 &= M28L;
        x12 += (x11 >> 28); x11 &= M28L;
        x13 += (x12 >> 28); x12 &= M28L;
        x14 += (x13 >> 28); x13 &= M28L;
        x15 += (x14 >> 28); x14 &= M28L;

//        assert x15 >>> 26 == 0L;

        byte[] r = new byte[SCALAR_BYTES];
        encode56(x00 | (x01 << 28), r,  0);
        encode56(x02 | (x03 << 28), r,  7);
        encode56(x04 | (x05 << 28), r, 14);
        encode56(x06 | (x07 << 28), r, 21);
        encode56(x08 | (x09 << 28), r, 28);
        encode56(x10 | (x11 << 28), r, 35);
        encode56(x12 | (x13 << 28), r, 42);
        encode56(x14 | (x15 << 28), r, 49);
//        r[SCALAR_BYTES - 1] = 0;
        return r;
    }

    private static void scalarMultBase(byte[] k, PointExt r)
    {
        precompute();

        pointSetNeutral(r);

        int[] n = new int[SCALAR_INTS + 1];
        decodeScalar(k, 0, n);

        // Recode the scalar into signed-digit form
        {
            n[SCALAR_INTS] = 4 + Nat.cadd(SCALAR_INTS, ~n[0] & 1, n, L, n);
//            int c = Nat.shiftDownBit(n.length, n, 0);                           assert c == (1 << 31);
            Nat.shiftDownBit(n.length, n, 0);
        }

        PointPrecomp p = new PointPrecomp();

        int cOff = PRECOMP_SPACING - 1;
        for (;;)
        {
            int tPos = cOff;

            for (int b = 0; b < PRECOMP_BLOCKS; ++b)
            {
                int w = 0;
                for (int t = 0; t < PRECOMP_TEETH; ++t)
                {
                    int tBit = n[tPos >>> 5] >>> (tPos & 0x1F);
                    w &= ~(1 << t);
                    w ^= (tBit << t);
                    tPos += PRECOMP_SPACING;
                }

                int sign = (w >>> (PRECOMP_TEETH - 1)) & 1;
                int abs = (w ^ -sign) & PRECOMP_MASK;

//                assert sign == 0 || sign == 1;
//                assert 0 <= abs && abs < PRECOMP_POINTS;

                pointLookup(b, abs, p);

                X448Field.cnegate(sign, p.x);

                pointAddPrecomp(p, r);
            }

            if (--cOff < 0)
            {
                break;
            }

            pointDouble(r);
        }
    }

    private static void scalarMultBaseEncoded(byte[] k, byte[] r, int rOff)
    {
        PointExt p = new PointExt();
        scalarMultBase(k, p);
        encodePoint(p, r, rOff);
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

        PointExt p = new PointExt();
        scalarMultBase(n, p);
        X448Field.copy(p.x, 0, x, 0);
        X448Field.copy(p.y, 0, y, 0);
    }

    private static void scalarMultStraussVar(int[] nb, int[] np, PointExt p, PointExt r)
    {
        precompute();

        final int width = 5;

        byte[] ws_b = getWNAF(nb, WNAF_WIDTH_BASE);
        byte[] ws_p = getWNAF(np, width);

        PointExt[] tp = pointPrecompVar(p, 1 << (width - 2));

        pointSetNeutral(r);

        int bit = 447;
        while (bit > 0 && (ws_b[bit] | ws_p[bit]) == 0)
        {
            --bit;
        }

        for (;;)
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

    public static void signPrehash(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] ctx, Xof ph, byte[] sig, int sigOff)
    {
        byte[] m = new byte[PREHASH_SIZE];
        if (PREHASH_SIZE != ph.doFinal(m, 0, PREHASH_SIZE))
        {
            throw new IllegalArgumentException("ph");
        }

        byte phflag = 0x01;

        implSign(sk, skOff, pk, pkOff, ctx, phflag, m, 0, m.length, sig, sigOff);
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
}
