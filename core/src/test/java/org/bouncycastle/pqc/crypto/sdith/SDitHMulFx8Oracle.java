package org.bouncycastle.pqc.crypto.sdith;

import org.bouncycastle.util.GF256;
import org.bouncycastle.util.Pack;

/**
 * Exhaustive oracle for {@link GF256#mulFx8} vs {@link SDitHGF256#mulNaive}.
 * Lives in this package to reach the package-private {@code mulNaive} reference.
 * NOT a JUnit test — run from main() before wiring the kernel into the matmul.
 */
public class SDitHMulFx8Oracle
{
    public static void main(String[] args)
    {
        long checks = 0;
        // 1) Every scalar x every byte, replicated across all 8 lanes.
        for (int s = 0; s < 256; ++s)
        {
            for (int b = 0; b < 256; ++b)
            {
                long v = 0;
                for (int lane = 0; lane < 8; ++lane)
                {
                    v |= (long)b << (8 * lane);
                }
                long got = GF256.mulFx8(s, v);
                int want = SDitHGF256.mulNaive(s, b);
                for (int lane = 0; lane < 8; ++lane)
                {
                    int gl = (int)((got >>> (8 * lane)) & 0xff);
                    if (gl != want)
                    {
                        throw new IllegalStateException("replicated mismatch s=" + s + " b=" + b
                            + " lane=" + lane + " got=" + gl + " want=" + want);
                    }
                    checks++;
                }
            }
        }
        // 2) Lane independence: every scalar x a mixed 8-byte pattern, checked
        //    per-lane against mulNaive, swept so each lane sees all 256 bytes.
        byte[] buf = new byte[8];
        for (int s = 0; s < 256; ++s)
        {
            for (int base = 0; base < 256; ++base)
            {
                for (int lane = 0; lane < 8; ++lane)
                {
                    buf[lane] = (byte)((base + lane * 37 + s * 11) & 0xff);
                }
                long v = Pack.littleEndianToLong(buf, 0);
                long got = GF256.mulFx8(s, v);
                for (int lane = 0; lane < 8; ++lane)
                {
                    int gl = (int)((got >>> (8 * lane)) & 0xff);
                    int want = SDitHGF256.mulNaive(s, buf[lane] & 0xff);
                    if (gl != want)
                    {
                        throw new IllegalStateException("mixed mismatch s=" + s + " base=" + base
                            + " lane=" + lane + " got=" + gl + " want=" + want);
                    }
                    checks++;
                }
            }
        }
        System.out.println("mulFx8 oracle OK: " + checks + " lane-checks, all match mulNaive");
    }
}
