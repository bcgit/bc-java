package org.bouncycastle.math.ec.rfc7748;

import java.security.SecureRandom;

import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.util.Arrays;

/**
 * A low-level implementation of X25519 (RFC 7748).
 * <p>
 * <b>Algorithm map.</b>
 * <ul>
 *   <li>{@link #generatePrivateKey} &mdash; 32 random bytes followed by
 *       {@link #clampPrivateKey} (RFC 7748 sec. 5 clamping: clear bits
 *       254..255 then 0..2, set bit 254).</li>
 *   <li>{@link #generatePublicKey} / {@link #scalarMultBase} &mdash;
 *       computed as {@code k * B} on the birationally-equivalent
 *       {@code edwards25519} curve via
 *       {@link Ed25519#scalarMultBaseYZ(Friend, byte[], int, int[], int[])}
 *       (a signed multi-comb in extended Edwards coordinates), then
 *       converted to the curve25519 {@code u} coordinate using the RFC
 *       7748 sec. 4.1 birational map {@code u = (1 + Y) / (1 - Y)}
 *       where {@code Y = y / z}.</li>
 *   <li>{@link #scalarMult} (key agreement) &mdash; Montgomery ladder on
 *       XZ-only projective coordinates per RFC 7748 sec. 5, with
 *       per-bit constant-time {@code cswap}; the
 *       {@code A24 = (A + 2) / 4} curve constant is precomputed from
 *       {@code A = 486662}. The final three doublings correspond to the
 *       always-cleared low bits of the scalar; these clear the cofactor
 *       to ensure a non-twist result.</li>
 *   <li>{@link #calculateAgreement} &mdash; {@link #scalarMult} followed
 *       by the RFC 7748 sec. 6.1 all-zero rejection.</li>
 * </ul>
 * <p>
 * <b>Side-channel scope.</b> Secret-scalar operations are written to be
 * constant-time at the Java level: the Montgomery ladder in
 * {@link #scalarMult} performs identical field operations per bit with
 * branchless {@code cswap}; {@link #scalarMultBase} routes through the
 * Ed25519 signed-comb, which walks all precomputed entries with mask-based
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
public abstract class X25519
{
    public static class Friend
    {
        private static final Friend INSTANCE = new Friend();
        private Friend() {}
    }

    public static final int POINT_SIZE = 32;
    public static final int SCALAR_SIZE = 32;

    private static class F extends X25519Field {};

    private static final int C_A = 486662;
    private static final int C_A24 = (C_A + 2)/4;

//    private static final int[] SQRT_NEG_486664 = { 0x03457E06, 0x03812ABF, 0x01A82CC6, 0x028A5BE8, 0x018B43A7,
//        0x03FC4F7E, 0x02C23700, 0x006BBD27, 0x03A30500, 0x001E4DDB };

    public static boolean calculateAgreement(byte[] k, int kOff, byte[] u, int uOff, byte[] r, int rOff)
    {
        scalarMult(k, kOff, u, uOff, r, rOff);
        return !Arrays.areAllZeroes(r, rOff, POINT_SIZE);
    }

    public static void clampPrivateKey(byte[] k)
    {
        if (k == null)
        {
            throw new NullPointerException("'k' cannot be null");
        }
        if (k.length != SCALAR_SIZE)
        {
            throw new IllegalArgumentException("k");
        }

        k[0              ] &= 0xF8;
        k[SCALAR_SIZE - 1] &= 0x7F;
        k[SCALAR_SIZE - 1] |= 0x40;
    }

    private static void decodeScalar(byte[] k, int kOff, int[] n)
    {
        for (int i = 0; i < 8; ++i)
        {
            n[i] = F.decode32(k, kOff + i * 4);
        }

        n[0] &= 0xFFFFFFF8;
        n[7] &= 0x7FFFFFFF;
        n[7] |= 0x40000000;
    }

    public static void generatePrivateKey(SecureRandom random, byte[] k)
    {
        if (random == null)
        {
            throw new NullPointerException("'random' cannot be null");
        }
        if (k == null)
        {
            throw new NullPointerException("'k' cannot be null");
        }
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

        F.apm(x, z, a, b);
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
        Ed25519.precompute();
    }

    public static void scalarMult(byte[] k, int kOff, byte[] u, int uOff, byte[] r, int rOff)
    {
        Arrays.validateSegment(k, kOff, SCALAR_SIZE);
        Arrays.validateSegment(u, uOff, POINT_SIZE);
        Arrays.validateSegment(r, rOff, POINT_SIZE);

        int[] n = new int[8];       decodeScalar(k, kOff, n);

        int[] x1 = F.create();      F.decode255(u, uOff, x1, 0);
        int[] x2 = F.create();      F.copy(x1, 0, x2, 0);
        int[] z2 = F.create();      z2[0] = 1;
        int[] x3 = F.create();      x3[0] = 1;
        int[] z3 = F.create();

        int[] t1 = F.create();
        int[] t2 = F.create();

//        assert n[7] >>> 30 == 1;

        int bit = 254, swap = 1;
        do
        {
            F.apm(x3, z3, t1, x3);
            F.apm(x2, z2, z3, x2);
            F.mul(t1, x2, t1);
            F.mul(x3, z3, x3);
            F.sqr(z3, z3);
            F.sqr(x2, x2);

            F.sub(z3, x2, t2);
            F.mul(t2, C_A24, z2);
            F.add(z2, x2, z2);
            F.mul(z2, t2, z2);
            F.mul(x2, z3, x2);

            F.apm(t1, x3, x3, z3);
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
        while (bit >= 3);

//        assert swap == 0;

        for (int i = 0; i < 3; ++i)
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
//        u[0] = 9;
//
//        scalarMult(k, kOff, u, 0, r, rOff);

        Arrays.validateSegment(k, kOff, SCALAR_SIZE);
        Arrays.validateSegment(r, rOff, POINT_SIZE);

        int[] y = F.create();
        int[] z = F.create();

        Ed25519.scalarMultBaseYZ(Friend.INSTANCE, k, kOff, y, z);

        // Birational map edwards25519 -> curve25519 (RFC 7748 sec. 4.1):
        //   u = (1 + Y) / (1 - Y),  where Y = y / z.
        // Computed projectively: y' := z + y, z' := z - y, then u = y' / z'.
        F.apm(z, y, y, z);

        F.inv(z, z);
        F.mul(y, z, y);

        F.normalize(y);
        F.encode(y, r, rOff);
    }
}
