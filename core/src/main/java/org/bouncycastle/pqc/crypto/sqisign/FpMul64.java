package org.bouncycastle.pqc.crypto.sqisign;

/**
 * Unsigned 64×64→high-64 multiply, factored out so the only Java-version-
 * dependent piece of the Phase I 64-bit-limb Montgomery kernel
 * ({@link FpMontHelper64}) lives in one tiny class that the Multi-Release
 * JAR overlay can replace.
 *
 * <p><b>This base version is Java 8.</b> It computes the high 64 bits of the
 * unsigned 128-bit product via four 32×32→64 sub-products (Hacker's Delight
 * style), and reports {@link #isHardware} == {@code false}. With HARDWARE false
 * the dispatch flag {@code FpMontHelper.USE_HW_MONT64} stays false, so on
 * Java 8 the SQIsign limb path keeps using the 32-bit-limb kernel
 * ({@link FpMontHelper}) — this software fallback is never on the hot path.</p>
 *
 * <p>The {@code src/main/jdk1.9} overlay replaces this class with a version
 * that uses {@link Math#multiplyHigh} (Java 9+, JIT-intrinsified to a single
 * MULX/UMULH instruction) and sets {@code HARDWARE = true}, enabling the fast
 * 64-bit-limb path. The JVM loads the overlay automatically on Java 9+ from
 * {@code META-INF/versions/9/} in the multi-release {@code bccore} jar.</p>
 */
final class FpMul64
{
    /**
     * {@code true} only in the Java 9+ overlay (where {@link #umulHi} uses
     * the hardware high-multiply intrinsic). Drives
     * {@code FpMontHelper.USE_HW_MONT64}: when false, the 64-bit-limb path is
     * disabled and the 32-bit-limb kernel is used instead.
     *
     * <p><b>Must be a method, not a {@code static final} constant.</b> A
     * {@code static final boolean} initialised from a constant expression is
     * inlined by javac into every consumer at compile time, so the base
     * value ({@code false}) would be baked into {@code FpMontHelper.class}
     * and the Multi-Release overlay swapping this class at runtime would have
     * no effect. A method call is resolved at runtime against the loaded
     * class (overlay on Java 9+), so the overlay is correctly honoured.</p>
     */
    static boolean isHardware()
    {
        return false;
    }

    private FpMul64()
    {
    }

    /**
     * High 64 bits of the unsigned 128-bit product {@code a * b}.
     * Software fallback: split each operand into 32-bit halves, form the
     * four cross-products (each fits in 64 bits since the inputs are < 2^32),
     * and recombine. Pure Java 8.
     */
    static long umulHi(long a, long b)
    {
        long aLo = a & 0xFFFFFFFFL;
        long aHi = a >>> 32;
        long bLo = b & 0xFFFFFFFFL;
        long bHi = b >>> 32;

        long t00 = aLo * bLo;   // bits [0,   64)
        long t01 = aLo * bHi;   // bits [32,  96)
        long t10 = aHi * bLo;   // bits [32,  96)
        long t11 = aHi * bHi;   // bits [64, 128)

        // Carry from bits [32,64) into bit 64.
        long cross = (t00 >>> 32) + (t01 & 0xFFFFFFFFL) + (t10 & 0xFFFFFFFFL);
        return t11 + (t01 >>> 32) + (t10 >>> 32) + (cross >>> 32);
    }
}
