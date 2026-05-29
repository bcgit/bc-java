package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;

/**
 * Storage cell for a GF(p) field element, dual-represented:
 *
 * <ul>
 *   <li>{@link #v} — canonical {@link BigInteger} in {@code [0, p)}; the
 *       fallback truth used in default (BigInteger) mode and by all
 *       level-independent code that needs a single integer.</li>
 *   <li>{@link #mont} — Montgomery-form limb array (size 16, big enough
 *       for lvl5); the truth in limbs mode after {@code FpLvlN.mul} or
 *       any Mont-domain op.</li>
 * </ul>
 *
 * <p>{@link #vInSync} and {@link #montInSync} flags track which
 * representation is current. The invariant is that <em>at least</em> one
 * is true at any time; both may be true after a {@code setZero} (zero is
 * universal) or after a {@code setOne} (canonical 1 is in {@code v}).
 * The {@link #level} byte (1/3/5, or 0 = unset) lets level-independent
 * helpers dispatch lazy {@link #ensureV(Fp)} materialisation to the
 * right {@code FpLvlNMont} when the cell came out of a level-aware
 * Mont-domain op.</p>
 *
 * <p>Cells must not be reused across SQIsign levels — every call site
 * already creates fresh cells per level, so the invariant holds.</p>
 */
final class
Fp
{
    public BigInteger v;

    /** Montgomery-form cache. Size 16 covers the widest level (lvl5). */
    final int[] mont = new int[16];

    /**
     * Pre-allocated scratch used by {@code FpLvlN.mul}/{@code sqr} as
     * the {@code fromMont} destination and by {@link #ensureV} during
     * lazy materialisation. Content is overwritten freely.
     */
    final int[] canonScratch = new int[16];

    /**
     * Phase I: 64-bit-limb Montgomery cache. 8 longs = 512 bits covers
     * the widest level (lvl5). When {@link FpMontHelper#USE_HW_MONT64} is
     * true, level-aware ops use this in place of {@link #mont} and call
     * {@link FpMontHelper64}'s kernel which uses {@code Math.multiplyHigh}
     * for ~2.25× kernel speedup vs the 32-bit-limb path.
     */
    final long[] mont64 = new long[8];

    /** Scratch for {@link FpLvl1Mont64#materializeV} and friends. */
    final long[] canonScratch64 = new long[8];

    /**
     * {@code true} iff {@link #v} is the canonical value of this cell.
     * Always {@code true} for the just-constructed zero cell.
     */
    boolean vInSync = true;

    /**
     * {@code true} iff {@link #mont} holds the Montgomery form of this
     * cell at its level. Always {@code true} for the just-constructed
     * zero cell ({@code 0 * R mod p = 0} for any R / p).
     */
    boolean montInSync = true;

    /**
     * SQIsign level this cell is associated with: 1, 3, or 5; or 0 if
     * never used in level-aware arithmetic. Set the first time the
     * cell flows through {@code FpLvlN.ensureMont} / {@code mul} /
     * {@code sqr} / {@code add} / etc.; used by {@link #ensureV} to
     * route lazy v-materialisation to the correct {@code FpLvlNMont}.
     */
    byte level = 0;

    public Fp()
    {
        this.v = BigInteger.ZERO;
    }

    public Fp(BigInteger v)
    {
        this.v = v;
        // mont/canonScratch initialised to zeros; mont is only in sync
        // if v happens to be 0.
        this.montInSync = (v.signum() == 0);
    }


    public Fp copy()
    {
        Fp c = new Fp();
        c.v = this.v;
        c.vInSync = this.vInSync;
        if (FpMontHelper.LIMBS_ENABLED)
        {
            // Copy only the representation the active kernel uses — the other
            // limb array is never read, so copying it is pure waste (Fp.copy
            // was ~8.5% of CPU in the Phase I profile).
            if (FpMontHelper.USE_HW_MONT64)
            {
                System.arraycopy(this.mont64, 0, c.mont64, 0, c.mont64.length);
            }
            else
            {
                System.arraycopy(this.mont, 0, c.mont, 0, c.mont.length);
            }
            c.montInSync = this.montInSync;
            c.level = this.level;
        }
        return c;
    }

    public boolean equals(Object o)
    {
        if (!(o instanceof Fp)) return false;
        Fp other = (Fp)o;
        ensureV(this);
        ensureV(other);
        return other.v.equals(this.v);
    }

    public int hashCode()
    {
        ensureV(this);
        return v.hashCode();
    }

    // ---- level-independent static helpers ----------------------------------

    /** Allocate a fresh zero cell. */
    public static Fp zero()
    {
        return new Fp();
    }

    /** Allocate a fresh one cell (canonical 1 is below every SQIsign prime). */
    public static Fp one()
    {
        return new Fp(BigInteger.ONE);
    }

    public static void setZero(Fp x)
    {
        x.v = BigInteger.ZERO;
        x.vInSync = true;
        if (FpMontHelper.LIMBS_ENABLED)
        {
            java.util.Arrays.fill(x.mont, 0);
            java.util.Arrays.fill(x.mont64, 0L);
            x.montInSync = true;
        }
    }

    public static void setOne(Fp x)
    {
        x.v = BigInteger.ONE;
        x.vInSync = true;
        if (FpMontHelper.LIMBS_ENABLED)
        {
            x.montInSync = false; // R mod p is level-specific; defer to FpLvlN.ensureMont
        }
    }

    /** Set {@code x} to a small unsigned long {@code val}. Canonical for
     *  {@code val < p} which holds for all SQIsign primes (≥ 250 bits). */
    public static void setSmall(Fp x, long val)
    {
        x.v = BigInteger.valueOf(val);
        x.vInSync = true;
        if (FpMontHelper.LIMBS_ENABLED)
        {
            x.montInSync = (val == 0L);
            if (x.montInSync)
            {
                java.util.Arrays.fill(x.mont, 0);
                java.util.Arrays.fill(x.mont64, 0L);
            }
        }
    }

    public static void copy(Fp dst, Fp src)
    {
        dst.v = src.v;
        dst.vInSync = src.vInSync;
        if (FpMontHelper.LIMBS_ENABLED)
        {
            if (FpMontHelper.USE_HW_MONT64)
            {
                System.arraycopy(src.mont64, 0, dst.mont64, 0, dst.mont64.length);
            }
            else
            {
                System.arraycopy(src.mont, 0, dst.mont, 0, dst.mont.length);
            }
            dst.montInSync = src.montInSync;
            dst.level = src.level;
        }
    }

    /**
     * Conditional swap: swap {@code a} and {@code b} when {@code ctl != 0}.
     * <p>
     * Constant-time on the Montgomery limb representation: the limb-array swap
     * runs unconditionally with a branchless XOR-mask (mask = −1 if ctl ≠ 0,
     * else 0), so the L1 "no data-dependent branches" property is preserved
     * for the CT-critical limb path. The BigInteger reference and bookkeeping
     * flags are still branched — Java cannot XOR object references and the
     * standard branchless alternative (a 2-element array indexed by the
     * secret bit) would substitute an L3 leak (data-dependent memory access)
     * for the L1 leak; the BigInteger arithmetic that flows from {@code v}
     * is structurally non-constant-time anyway (JDK {@code BigInteger.multiply}
     * / {@code mod} / {@code modPow} are not CT), so CT-critical SQIsign
     * signing must run on the {@link FpMontHelper#LIMBS_ENABLED} path.
     * </p>
     */
    public static void cswap(Fp a, Fp b, int ctl)
    {
        // Normalise any-nonzero ctl to a -1/0 mask. Works for ctl in
        // {0, 1, -1, 0xFFFFFFFF, ...}: ctl|-ctl has the sign bit set iff
        // ctl != 0, so arithmetic shift right by 31 broadcasts to -1 / 0.
        int mask = (ctl | -ctl) >> 31;

        if (FpMontHelper.LIMBS_ENABLED)
        {
            // Branchless XOR-mask swap of the active limb representation.
            if (FpMontHelper.USE_HW_MONT64)
            {
                long lmask = (long)mask;
                for (int i = 0; i < a.mont64.length; i++)
                {
                    long t = (a.mont64[i] ^ b.mont64[i]) & lmask;
                    a.mont64[i] ^= t;
                    b.mont64[i] ^= t;
                }
            }
            else
            {
                for (int i = 0; i < a.mont.length; i++)
                {
                    int t = (a.mont[i] ^ b.mont[i]) & mask;
                    a.mont[i] ^= t;
                    b.mont[i] ^= t;
                }
            }
        }

        // BigInteger reference / bookkeeping flag swap: branched (see javadoc).
        if (mask != 0)
        {
            BigInteger tmpV = a.v;
            a.v = b.v;
            b.v = tmpV;
            boolean tmpVS = a.vInSync;
            a.vInSync = b.vInSync;
            b.vInSync = tmpVS;
            if (FpMontHelper.LIMBS_ENABLED)
            {
                boolean s = a.montInSync;
                a.montInSync = b.montInSync;
                b.montInSync = s;
                byte tl = a.level;
                a.level = b.level;
                b.level = tl;
            }
        }
    }

    /**
     * Constant-time select: {@code d ← a1} if {@code ctl != 0}, else
     * {@code d ← a0}. Same CT-scope rules as {@link #cswap(Fp, Fp, int)} — the
     * Montgomery limb representation is selected branchlessly via XOR-mask;
     * BigInteger reference + flag selection remains branched. See cswap javadoc.
     */
    public static void select(Fp d, Fp a0, Fp a1, int ctl)
    {
        int mask = (ctl | -ctl) >> 31;

        if (FpMontHelper.LIMBS_ENABLED)
        {
            // Branchless XOR-mask select: d[i] = a0[i] ^ ((a0[i] ^ a1[i]) & mask).
            if (FpMontHelper.USE_HW_MONT64)
            {
                long lmask = (long)mask;
                for (int i = 0; i < d.mont64.length; i++)
                {
                    d.mont64[i] = a0.mont64[i] ^ ((a0.mont64[i] ^ a1.mont64[i]) & lmask);
                }
            }
            else
            {
                for (int i = 0; i < d.mont.length; i++)
                {
                    d.mont[i] = a0.mont[i] ^ ((a0.mont[i] ^ a1.mont[i]) & mask);
                }
            }
        }

        Fp src = (mask == 0) ? a0 : a1;
        d.v = src.v;
        d.vInSync = src.vInSync;
        if (FpMontHelper.LIMBS_ENABLED)
        {
            d.montInSync = src.montInSync;
            d.level = src.level;
        }
    }

    /**
     * Lazily materialise {@link #v} from {@link #mont} for cells whose
     * latest update came from a Mont-domain op. Dispatches on
     * {@link #level} to the correct {@code FpLvlNMont}. No-op when
     * {@code vInSync} is already true.
     */
    static void ensureV(Fp x)
    {
        if (x.vInSync)
        {
            return;
        }
        // vInSync == false implies a level-aware op produced this cell,
        // so level should be set. Dispatch to 64-bit materialiser when on
        // the Phase I path, else to the 32-bit one.
        if (FpMontHelper.USE_HW_MONT64)
        {
            switch (x.level)
            {
                case 1: FpLvl1Mont64.materializeV(x); break;
                case 3: FpLvl3Mont64.materializeV(x); break;
                case 5: FpLvl5Mont64.materializeV(x); break;
                default:
                    throw new IllegalStateException(
                        "Fp.ensureV: vInSync=false but level=" + x.level);
            }
        }
        else
        {
            switch (x.level)
            {
                case 1: FpLvl1Mont.materializeV(x); break;
                case 3: FpLvl3Mont.materializeV(x); break;
                case 5: FpLvl5Mont.materializeV(x); break;
                default:
                    throw new IllegalStateException(
                        "Fp.ensureV: vInSync=false but level=" + x.level);
            }
        }
        x.vInSync = true;
    }

    /** 0xFFFFFFFF if {@code a == 0}, else 0. Level-independent: works on
     *  whichever representation is in sync. Zero is universal in both
     *  canonical and Montgomery form ({@code 0 * R mod p = 0}). */
    public static int isZero(Fp a)
    {
        if (FpMontHelper.LIMBS_ENABLED && a.montInSync)
        {
            // Zero is universal: 0 * R mod p = 0 in either 32-bit or 64-bit
            // form. Constant-time fold over all limbs (no early-exit branch
            // on secret data); broadcast the zero-ness to a mask at the end.
            if (FpMontHelper.USE_HW_MONT64)
            {
                long acc = 0L;
                for (int i = 0; i < a.mont64.length; i++)
                {
                    acc |= a.mont64[i];
                }
                // acc == 0 → -1; acc != 0 → 0. Branchless via two-step OR.
                long nz = acc | -acc;        // sign bit set iff acc != 0
                return (int)(~(nz >> 63));   // -1 if acc == 0, else 0
            }
            int accI = 0;
            for (int i = 0; i < a.mont.length; i++)
            {
                accI |= a.mont[i];
            }
            int nzI = accI | -accI;
            return ~(nzI >> 31);
        }
        return a.v.signum() == 0 ? 0xFFFFFFFF : 0;
    }

    public static int isEqual(Fp a, Fp b)
    {
        if (FpMontHelper.LIMBS_ENABLED && a.montInSync && b.montInSync)
        {
            // Both cells are in Mont form, same level (codebase invariant).
            // Constant-time fold over the XOR of all limbs.
            if (FpMontHelper.USE_HW_MONT64)
            {
                long acc = 0L;
                for (int i = 0; i < a.mont64.length; i++)
                {
                    acc |= (a.mont64[i] ^ b.mont64[i]);
                }
                long nz = acc | -acc;
                return (int)(~(nz >> 63));
            }
            int accI = 0;
            for (int i = 0; i < a.mont.length; i++)
            {
                accI |= (a.mont[i] ^ b.mont[i]);
            }
            int nzI = accI | -accI;
            return ~(nzI >> 31);
        }
        ensureV(a);
        ensureV(b);
        return a.v.equals(b.v) ? 0xFFFFFFFF : 0;
    }
}
