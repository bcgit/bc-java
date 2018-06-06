package org.bouncycastle.math.ec.rfc8032;

import java.math.BigInteger;

public abstract class Ed448
{
    private static final int POINT_BYTES = 57;
    private static final int SCALAR_INTS = 15;
    private static final int SCALAR_BYTES = 57;

    public static final int PUBLIC_KEY_SIZE = POINT_BYTES;
    public static final int SECRET_KEY_SIZE = 57;
    public static final int SIGNATURE_SIZE = POINT_BYTES + SCALAR_BYTES;

    private static final BigInteger P = BigInteger.ONE.shiftLeft(448).subtract(BigInteger.ONE.shiftLeft(224)).subtract(BigInteger.ONE);
    private static final BigInteger L = BigInteger.ONE.shiftLeft(446).subtract(
        new BigInteger("8335DC163BB124B65129C96FDE933D8D723A70AADC873D6D54A7BB0D", 16));

    private static final int[] B_x = new int[] { 0x070CC05E, 0x026A82BC, 0x00938E26, 0x080E18B0, 0x0511433B, 0x0F72AB66, 0x0412AE1A,
        0x0A3D3A46, 0x0A6DE324, 0x00F1767E, 0x04657047, 0x036DA9E1, 0x05A622BF, 0x0ED221D1, 0x066BED0D, 0x04F1970C };
    private static final int[] B_y = new int[] { 0x0230FA14, 0x008795BF, 0x07C8AD98, 0x0132C4ED, 0x09C4FDBD, 0x01CE67C3, 0x073AD3FF,
        0x005A0C2D, 0x07789C1E, 0x0A398408, 0x0A73736C, 0x0C7624BE, 0x003756C9, 0x02488762, 0x016EB6BC, 0x0693F467 };

    public static void generatePublicKey(byte[] ctx, byte[] sk, int skOff, byte[] pk, int pkOff)
    {
    }

    public static void precompute()
    {
    }

    public static void sign(byte[] ctx, byte[] sk, int skOff, byte[] m, int mOff, int mLen, byte[] sig, int sigOff)
    {
    }

    public static void sign(byte[] ctx, byte[] sk, int skOff, byte[] pk, int pkOff, byte[] m, int mOff, int mLen, byte[] sig, int sigOff)
    {
    }

    public static boolean verify(byte[] ctx, byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] m, int mOff, int mLen)
    {
        return false;
    }
}
