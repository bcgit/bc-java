package org.bouncycastle.util;

/**
 * GF(2^4) helpers.
 *
 * @deprecated moved to {@link org.bouncycastle.math.raw.GF16}; this type now
 * delegates there and will be removed in a future release.
 */
@Deprecated
public class GF16
{
    /**
     * @deprecated use {@link org.bouncycastle.math.raw.GF16#mul(byte, byte)}.
     */
    @Deprecated
    public static byte mul(byte a, byte b)
    {
        return org.bouncycastle.math.raw.GF16.mul(a, b);
    }

    /**
     * @deprecated use {@link org.bouncycastle.math.raw.GF16#mul(int, int)}.
     */
    @Deprecated
    public static int mul(int a, int b)
    {
        return org.bouncycastle.math.raw.GF16.mul(a, b);
    }

    /**
     * @deprecated use {@link org.bouncycastle.math.raw.GF16#inv(byte)}.
     */
    @Deprecated
    public static byte inv(byte a)
    {
        return org.bouncycastle.math.raw.GF16.inv(a);
    }

    /**
     * @deprecated use {@link org.bouncycastle.math.raw.GF16#decode(byte[], byte[], int)}.
     */
    @Deprecated
    public static void decode(byte[] input, byte[] output, int outputLen)
    {
        org.bouncycastle.math.raw.GF16.decode(input, output, outputLen);
    }

    /**
     * @deprecated use {@link org.bouncycastle.math.raw.GF16#decode(byte[], int, byte[], int, int)}.
     */
    @Deprecated
    public static void decode(byte[] input, int inOff, byte[] output, int outOff, int outputLen)
    {
        org.bouncycastle.math.raw.GF16.decode(input, inOff, output, outOff, outputLen);
    }

    /**
     * @deprecated use {@link org.bouncycastle.math.raw.GF16#encode(byte[], byte[], int)}.
     */
    @Deprecated
    public static void encode(byte[] input, byte[] output, int inputLen)
    {
        org.bouncycastle.math.raw.GF16.encode(input, output, inputLen);
    }

    /**
     * @deprecated use {@link org.bouncycastle.math.raw.GF16#encode(byte[], byte[], int, int)}.
     */
    @Deprecated
    public static void encode(byte[] input, byte[] output, int outOff, int inputLen)
    {
        org.bouncycastle.math.raw.GF16.encode(input, output, outOff, inputLen);
    }

    /**
     * @deprecated use {@link org.bouncycastle.math.raw.GF16#innerProduct(byte[], int, byte[], int, int)}.
     */
    @Deprecated
    public static byte innerProduct(byte[] a, int aOff, byte[] b, int bOff, int rank)
    {
        return org.bouncycastle.math.raw.GF16.innerProduct(a, aOff, b, bOff, rank);
    }
}
