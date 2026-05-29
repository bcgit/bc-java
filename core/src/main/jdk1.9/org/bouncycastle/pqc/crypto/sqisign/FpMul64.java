package org.bouncycastle.pqc.crypto.sqisign;

/**
 * Java 9+ Multi-Release overlay of {@link FpMul64}. Replaces the Java 8
 * software fallback with {@link Math#multiplyHigh(long, long)} — added in
 * Java 9 and JIT-intrinsified to a single hardware instruction (MULX on
 * x86-64 BMI2, MULQ on x86-64 legacy, UMULH on ARM64). Sets
 * {@code HARDWARE = true} so {@code FpMontHelper.USE_HW_MONT64} enables the
 * fast 64-bit-limb Montgomery kernel.
 *
 * <p>Packaged under {@code META-INF/versions/9/} in the multi-release
 * {@code bccore} jar; the JVM loads this in place of the base class on
 * Java 9+. The base module ({@code src/main/java}) still compiles against
 * Java 8 — this file is compiled separately with {@code --release 9}.</p>
 *
 * <p>Standalone bench measured the 64-bit kernel built on this intrinsic at
 * ~2.25× the 32-bit-limb kernel on the lvl1 prime; end-to-end this yields
 * ~1.85× steady-state speedup over the BigInteger-Barrett default.</p>
 */
final class FpMul64
{
    /** True: this overlay uses the hardware high-multiply intrinsic.
     *  Method (not constant) so the MR-jar overlay is honoured at runtime —
     *  see the base {@link FpMul64#isHardware()} for why. */
    static boolean isHardware()
    {
        return true;
    }

    private FpMul64()
    {
    }

    /**
     * High 64 bits of the unsigned 128-bit product {@code a * b}.
     * {@link Math#multiplyHigh} returns the high half of the <em>signed</em>
     * product; the two correction terms convert it to unsigned via the
     * identity {@code unsignedHigh = signedHigh + (a<0 ? b : 0) + (b<0 ? a : 0)}.
     */
    static long umulHi(long a, long b)
    {
        long signedHi = Math.multiplyHigh(a, b);
        return signedHi + ((a >> 63) & b) + ((b >> 63) & a);
    }
}
