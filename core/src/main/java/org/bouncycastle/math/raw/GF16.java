package org.bouncycastle.math.raw;

public class GF16
{
    // SWAR per-nibble masks for the bitsliced GF(16) multiply-by-x step.
    private static final long NIBBLE_LSBS = 0x7777777777777777L;
    private static final long NIBBLE_MSBS = 0x8888888888888888L;

    /**
     * One step of the bitsliced, word-parallel GF(16) scalar-times-vector
     * multiply-accumulate. Returns the contribution to XOR into the accumulator
     * for a single 16-nibble packed input limb {@code v}, given the four
     * broadcast scalar-bit masks {@code m0..m3} (each 0 or -1, one per bit of
     * the GF(16) scalar). The caller hoists the mask computation outside its
     * limb loop.
     * <p>
     * This is the constant-time, table-free GF(16) kernel shared by UOV's
     * {@code GF.vecMadd16} and MAYO's {@code GF16Utils.mVecMulAdd}: a mask-select
     * on the scalar bits plus a SWAR multiply-by-x that folds x+1 (0x3) per
     * nibble for the field polynomial x^4 + x + 1. No data-dependent branch and
     * no secret-indexed table.
     *
     * @param v  16 GF(16) nibbles packed into a long.
     * @param m0 broadcast mask (0 or -1) for scalar bit 0.
     * @param m1 broadcast mask (0 or -1) for scalar bit 1.
     * @param m2 broadcast mask (0 or -1) for scalar bit 2.
     * @param m3 broadcast mask (0 or -1) for scalar bit 3.
     * @return the multiply-accumulate contribution for this limb.
     */
    public static long mulAddStep16(long v, long m0, long m1, long m2, long m3)
    {
        long r = v & m0;
        long msb3 = (v & NIBBLE_MSBS) >>> 3;
        v = ((v & NIBBLE_LSBS) << 1) ^ (msb3 + (msb3 << 1));
        r ^= v & m1;
        msb3 = (v & NIBBLE_MSBS) >>> 3;
        v = ((v & NIBBLE_LSBS) << 1) ^ (msb3 + (msb3 << 1));
        r ^= v & m2;
        msb3 = (v & NIBBLE_MSBS) >>> 3;
        v = ((v & NIBBLE_LSBS) << 1) ^ (msb3 + (msb3 << 1));
        r ^= v & m3;
        return r;
    }

    /**
     * GF(16) multiplication mod x^4 + x + 1.
     * <p>
     * Table-free, branch-free carryless multiply followed by reduction modulo x^4 + x + 1, so the
     * multiply carries no secret-indexed memory access (no L3 cache-timing side channel) &mdash; the
     * form used by the SNOVA and MAYO reference implementations' production (Opt / AVX2) builds.
     * Please ensure a &lt;= 0x0F and b &lt;= 0x0F.
     *
     * @param a an element in GF(16) (only the lower 4 bits are used)
     * @param b an element in GF(16) (only the lower 4 bits are used)
     * @return the product a * b in GF(16)
     */
    public static byte mul(byte a, byte b)
    {
        return (byte)mul((int)a, (int)b);
    }

    /**
     * GF(16) multiplication mod x^4 + x + 1; table-free, branch-free (see {@link #mul(byte, byte)}).
     * Please ensure a &lt;= 0x0F and b &lt;= 0x0F.
     *
     * @param a an element in GF(16) (only the lower 4 bits are used)
     * @param b an element in GF(16) (only the lower 4 bits are used)
     * @return the product a * b in GF(16)
     */
    public static int mul(int a, int b)
    {
        // carryless multiply: XOR the b-shifts selected by the bits of a
        int p = (a & 1) * b;
        p ^= (a & 2) * b;
        p ^= (a & 4) * b;
        p ^= (a & 8) * b;
        // reduce mod x^4 + x + 1: fold the high nibble back (x^4 = x + 1)
        int topP = p & 0xF0;
        return (p ^ (topP >> 4) ^ (topP >> 3)) & 0x0F;
    }

    /**
     * Byte-lane parallel GF(16) multiply: multiplies the single GF(16) scalar {@code a} into up to
     * eight GF(16) elements packed one-per-byte in {@code b} (each in the low nibble of its byte), all
     * at once and table-free. The batched, constant-time form of {@link #mul(int, int)} used to
     * multiply a scalar by a whole packed matrix row (the SNOVA / MAYO {@code mul_fx8}).
     *
     * @param a a GF(16) scalar (only the lower 4 bits are used)
     * @param b up to eight GF(16) elements, one per byte lane
     * @return the eight products, one per byte lane
     */
    public static long mulFx8(int a, long b)
    {
        long p = (a & 1) * b;
        p ^= (a & 2) * b;
        p ^= (a & 4) * b;
        p ^= (a & 8) * b;
        long topP = p & 0xF0F0F0F0F0F0F0F0L;
        return (p ^ (topP >>> 4) ^ (topP >>> 3)) & 0x0F0F0F0F0F0F0F0FL;
    }

    /**
     * Constant-time GF(16) squaring over x^4 + x + 1. Squaring is GF(2)-linear,
     * so {@code a^2} is just the bit-spread of {@code a} (interleave a zero
     * between each bit, via {@link Interleave#expand4to8(int)}) reduced mod 0x13.
     * {@code x^4 = x + 1} means the folded-down high nibble multiplies by 0x3,
     * computed branchlessly as {@code d ^ (d<<1)} = {@code d * (1 + x)}; one fold
     * suffices here (unlike GF(256)) because 0x3 is degree 1. Returns the same
     * value as {@link #mul(int, int) mul(a, a)} but with no per-term work —
     * table-free, branchless, and faster (~1.35x on HotSpot C2), so it replaces
     * the squarings in {@link #inv(int)}.
     */
    public static int sqr(int a)
    {
        int c = Interleave.expand4to8(a);  // a^2 unreduced: bits 0,2,4,6
        int d = c >>> 4;                   // high bits -> 0,2
        c &= 0xf;
        return c ^ d ^ (d << 1);           // + d*(1+x) = d*0x3
    }

    /**
     * Multiplicative inverse in GF(16), table-free: a^14 = a^-1 (since a^15 = 1 for a != 0; 0 maps to
     * 0), so the inverse carries no secret-indexed memory access. Matches the SNOVA / MAYO reference
     * {@code gf16_inv} / {@code inverse_f}.
     */
    public static byte inv(byte a)
    {
        return (byte)inv((int)a);
    }

    /**
     * Multiplicative inverse in GF(16); table-free, branch-free (see {@link #inv(byte)}).
     * The three squarings go through {@link #sqr(int)}; the two genuine products
     * through {@link #mul(int, int)}.
     *
     * @param a an element in GF(16) (only the lower 4 bits are used)
     * @return the inverse a^-1 in GF(16), or 0 when {@code a == 0}
     */
    public static int inv(int a)
    {
        int x = a & 0x0F;
        int a2 = sqr(x);
        int a4 = sqr(a2);
        int a8 = sqr(a4);
        int a6 = mul(a2, a4);
        return mul(a8, a6);
    }

    /**
     * Decodes an encoded byte array.
     * Each byte in the input contains two nibbles (4-bit values); the lower nibble is stored first,
     * followed by the upper nibble.
     *
     * @param input     the input byte array (each byte holds two 4-bit values)
     * @param output    the output array that will hold the decoded nibbles (one per byte)
     * @param outputLen the total number of nibbles to decode
     */
    public static void decode(byte[] input, byte[] output, int outputLen)
    {
        int i, decIndex = 0, blocks = outputLen >> 1;
        // Process pairs of nibbles from each byte
        for (i = 0; i < blocks; i++)
        {
            // Extract the lower nibble
            output[decIndex++] = (byte)(input[i] & 0x0F);
            // Extract the upper nibble (shift right 4 bits)
            output[decIndex++] = (byte)((input[i] >>> 4) & 0x0F);
        }
        // If there is an extra nibble (odd number of nibbles), decode only the lower nibble
        if ((outputLen & 1) == 1)
        {
            output[decIndex] = (byte)(input[i] & 0x0F);
        }
    }

    public static void decode(byte[] input, int inOff, byte[] output, int outOff, int outputLen)
    {
        // Process pairs of nibbles from each byte
        int blocks = outputLen >> 1;
        for (int i = 0; i < blocks; i++)
        {
            // Extract the lower nibble
            output[outOff++] = (byte)(input[inOff] & 0x0F);
            // Extract the upper nibble (shift right 4 bits)
            output[outOff++] = (byte)((input[inOff++] >>> 4) & 0x0F);
        }
        // If there is an extra nibble (odd number of nibbles), decode only the lower nibble
        if ((outputLen & 1) == 1)
        {
            output[outOff] = (byte)(input[inOff] & 0x0F);
        }
    }

    /**
     * Encodes an array of 4-bit values into a byte array.
     * Two 4-bit values are packed into one byte, with the first nibble stored in the lower 4 bits
     * and the second nibble stored in the upper 4 bits.
     *
     * @param input    the input array of 4-bit values (stored as bytes, only lower 4 bits used)
     * @param output   the output byte array that will hold the encoded bytes
     * @param inputLen the number of nibbles in the input array
     */
    public static void encode(byte[] input, byte[] output, int inputLen)
    {
        int i, inOff = 0, blocks = inputLen >> 1;
        // Process pairs of 4-bit values
        for (i = 0; i < blocks; i++)
        {
            int lowerNibble = input[inOff++] & 0x0F;
            int upperNibble = (input[inOff++] & 0x0F) << 4;
            output[i] = (byte)(lowerNibble | upperNibble);
        }
        // If there is an extra nibble (odd number of nibbles), store it directly in lower 4 bits.
        if ((inputLen & 1) == 1)
        {
            output[i] = (byte)(input[inOff] & 0x0F);
        }
    }

    public static void encode(byte[] input, byte[] output, int outOff, int inputLen)
    {
        int i, inOff = 0, blocks = inputLen >> 1;
        // Process pairs of 4-bit values
        for (i = 0; i < blocks; i++)
        {
            int lowerNibble = input[inOff++] & 0x0F;
            int upperNibble = (input[inOff++] & 0x0F) << 4;
            output[outOff++] = (byte)(lowerNibble | upperNibble);
        }
        // If there is an extra nibble (odd number of nibbles), store it directly in lower 4 bits.
        if ((inputLen & 1) == 1)
        {
            output[outOff] = (byte)(input[inOff] & 0x0F);
        }
    }

    public static byte innerProduct(byte[] a, int aOff, byte[] b, int bOff, int rank)
    {
        byte result = 0;
        for (int k = 0; k < rank; ++k, bOff += rank)
        {
            result ^= mul(a[aOff++], b[bOff]);
        }
        return result;
    }
}
