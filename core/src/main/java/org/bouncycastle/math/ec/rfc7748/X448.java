package org.bouncycastle.math.ec.rfc7748;

import java.security.SecureRandom;

import org.bouncycastle.math.ec.rfc8032.Ed448;
import org.bouncycastle.util.Arrays;

/**
 * A low-level implementation of X448 (RFC 7748).
 * <p>
 * <b>Algorithm map.</b>
 * <ul>
 *   <li>{@link #generatePrivateKey} &mdash; 56 random bytes followed by
 *       {@link #clampPrivateKey} (RFC 7748 sec. 5 clamping: clear bits
 *       0..1, set bit 447).</li>
 *   <li>{@link #generatePublicKey} / {@link #scalarMultBase} &mdash;
 *       computed as {@code k * B} on the 4-isogenous {@code edwards448} curve
 *       via {@link Ed448#scalarMultBaseXY(Friend, byte[], int, int[], int[])}
 *       (a signed multi-comb in projective Edwards coordinates), then
 *       converted to the curve448 {@code u} coordinate using the RFC
 *       7748 sec. 4.2 4-isogeny map {@code u = (y / x)^2}.</li>
 *   <li>{@link #scalarMult} (key agreement) &mdash; Montgomery ladder on
 *       XZ-only projective coordinates per RFC 7748 sec. 5, with
 *       per-bit constant-time {@code cswap}; the
 *       {@code A24 = (A + 2) / 4} curve constant is precomputed from
 *       {@code A = 156326}. The final two doublings correspond to the
 *       always-cleared low bits of the scalar; these clear the cofactor
 *       to ensure a non-twist result.</li>
 *   <li>{@link #calculateAgreement} &mdash; {@link #scalarMult} followed
 *       by the RFC 7748 sec. 6.2 all-zero rejection.</li>
 * </ul>
 * <p>
 * <b>Side-channel scope.</b> Secret-scalar operations are written to be
 * constant-time at the Java level: the Montgomery ladder in
 * {@link #scalarMult} performs identical field operations per bit with
 * branchless {@code cswap}; {@link #scalarMultBase} routes through the
 * Ed448 signed-comb, which walks all precomputed entries with mask-based
 * {@code cmov} rather than a secret-indexed array load and applies
 * conditional negation by XOR-with-mask; the final modular inverse uses
 * constant-time {@code Mod.modOddInverse}. The all-zero rejection in
 * {@link #calculateAgreement} runs an OR-accumulator and only leaks the
 * RFC-mandated public rejection criterion. This is sufficient against a
 * remote network timing attacker but is not a substitute for a constant-time
 * native implementation against a co-located cache-line-resolution
 * adversary &mdash; JVM-level timing variance from JIT, GC and cache
 * eviction is not addressable in pure Java.
 */
public abstract class X448
{
    public static class Friend
    {
        private static final Friend INSTANCE = new Friend();
        private Friend() {}
    }

    public static final int POINT_SIZE = 56;
    public static final int SCALAR_SIZE = 56;

    private static class F extends X448Field {};

    private static final int C_A = 156326;
    private static final int C_A24 = (C_A + 2)/4;

//    private static final int[] SQRT_156324 = { 0x0551B193, 0x07A21E17, 0x0E635AD3, 0x00812ABB, 0x025B3F99, 0x01605224,
//        0x0AF8CB32, 0x0D2E7D68, 0x06BA50FD, 0x08E55693, 0x0CB08EB4, 0x02ABEBC1, 0x051BA0BB, 0x02F8812E, 0x0829B611,
//        0x0BA4D3A0 };

    public static boolean calculateAgreement(byte[] k, int kOff, byte[] u, int uOff, byte[] r, int rOff)
    {
        scalarMult(k, kOff, u, uOff, r, rOff);
        return !Arrays.areAllZeroes(r, rOff, POINT_SIZE);
    }

    public static void clampPrivateKey(byte[] k)
    {
        if (k.length != SCALAR_SIZE)
        {
            throw new IllegalArgumentException("k");
        }

        k[0] &= 0xFC;
        k[SCALAR_SIZE - 1] |= 0x80;
    }

    private static void decodeScalar(byte[] k, int kOff, int[] n)
    {
        for (int i = 0; i < 14; ++i)
        {
            n[i] = F.decode32(k, kOff + i * 4);
        }

        n[ 0] &= 0xFFFFFFFC;
        n[13] |= 0x80000000;
    }

    public static void generatePrivateKey(SecureRandom random, byte[] k)
    {
        if (k.length != SCALAR_SIZE)
        {
            throw new IllegalArgumentException("k");
        }

        random.nextBytes(k);

        clampPrivateKey(k);
    }

    public static void generatePublicKey(byte[] k, int kOff, byte[] r, int rOff)
    {
        scalarMultBase(k, kOff, r, rOff);
    }

    private static void pointDouble(int[] x, int[] z)
    {
        int[] a = F.create();
        int[] b = F.create();

//        F.apm(x, z, a, b);
        F.add(x, z, a);
        F.sub(x, z, b);
        F.sqr(a, a);
        F.sqr(b, b);
        F.mul(a, b, x);
        F.sub(a, b, a);
        F.mul(a, C_A24, z);
        F.add(z, b, z);
        F.mul(z, a, z);
    }

    public static void precompute()
    {
        Ed448.precompute();
    }

    public static void scalarMult(byte[] k, int kOff, byte[] u, int uOff, byte[] r, int rOff)
    {
        int[] n = new int[14];      decodeScalar(k, kOff, n);

        int[] x1 = F.create();      F.decode448(u, uOff, x1, 0);
        int[] x2 = F.create();      F.copy(x1, 0, x2, 0);
        int[] z2 = F.create();      z2[0] = 1;
        int[] x3 = F.create();      x3[0] = 1;
        int[] z3 = F.create();

        int[] t1 = F.create();
        int[] t2 = F.create();

//        assert n[13] >>> 31 == 1;

        int bit = 447, swap = 1;
        do
        {
//            F.apm(x3, z3, t1, x3);
            F.add(x3, z3, t1);
            F.sub(x3, z3, x3);
//            F.apm(x2, z2, z3, x2);
            F.add(x2, z2, z3);
            F.sub(x2, z2, x2);

            F.mul(t1, x2, t1);
            F.mul(x3, z3, x3);
            F.sqr(z3, z3);
            F.sqr(x2, x2);

            F.sub(z3, x2, t2);
            F.mul(t2, C_A24, z2);
            F.add(z2, x2, z2);
            F.mul(z2, t2, z2);
            F.mul(x2, z3, x2);

//            F.apm(t1, x3, x3, z3);
            F.sub(t1, x3, z3);
            F.add(t1, x3, x3);
            F.sqr(x3, x3);
            F.sqr(z3, z3);
            F.mul(z3, x1, z3);

            --bit;

            int word = bit >>> 5, shift = bit & 0x1F;
            int kt = (n[word] >>> shift) & 1;
            swap ^= kt;
            F.cswap(swap, x2, x3);
            F.cswap(swap, z2, z3);
            swap = kt;
        }
        while (bit >= 2);

//        assert swap == 0;

        for (int i = 0; i < 2; ++i)
        {
            pointDouble(x2, z2);
        }

        F.inv(z2, z2);
        F.mul(x2, z2, x2);

        F.normalize(x2);
        F.encode(x2, r, rOff);
    }

    public static void scalarMultBase(byte[] k, int kOff, byte[] r, int rOff)
    {
        // Equivalent (but much slower)
//        byte[] u = new byte[POINT_SIZE];
//        u[0] = 5;
//
//        scalarMult(k, kOff, u, 0, r, rOff);

        int[] x = F.create();
        int[] y = F.create();

        Ed448.scalarMultBaseXY(Friend.INSTANCE, k, kOff, x, y);

        // 4-isogeny map edwards448 -> curve448 (RFC 7748 sec. 4.2): u = (y / x)^2.
        // The Ed448 comb returns the X, Y of a result in projective coordinates (with Z elided);
        // invert x and square the ratio.
        F.inv(x, x);
        F.mul(x, y, x);
        F.sqr(x, x);

        F.normalize(x);
        F.encode(x, r, rOff);
    }
}
