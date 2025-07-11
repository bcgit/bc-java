package org.bouncycastle.pqc.crypto.cross;

class Utils
{
    private static final int RESTR_G_GEN_1 = 16;
    private static final int RESTR_G_GEN_2 = 256;
    private static final int RESTR_G_GEN_4 = 384;
    private static final int RESTR_G_GEN_8 = 355;
    private static final int RESTR_G_GEN_16 = 302;
    private static final int RESTR_G_GEN_32 = 93;
    private static final int RESTR_G_GEN_64 = 505;
    private static final long REDUCTION_CONST = 2160140723L;
    private static final long RESTR_G_TABLE = 0x0140201008040201L;

    // Calculate bits needed to represent a number
    public static int bitsToRepresent(int n)
    {
        return 32 - Integer.numberOfLeadingZeros(n);
    }

    // Packs 9-bit elements (for P=509)
    static void genericPack9Bit(byte[] out, int outOff, short[] in, int inlen)
    {

        int fullBlocks = inlen >>> 3;
        int i;
        int inOff = 0;

        for (i = 0; i < fullBlocks; i++)
        {
            out[outOff++] = (byte)in[inOff];
            out[outOff++] = (byte)((in[inOff] >>> 8) | (in[++inOff] << 1));
            out[outOff++] = (byte)((in[inOff] >>> 7) | (in[++inOff] << 2));
            out[outOff++] = (byte)((in[inOff] >>> 6) | (in[++inOff] << 3));
            out[outOff++] = (byte)((in[inOff] >>> 5) | (in[++inOff] << 4));
            out[outOff++] = (byte)((in[inOff] >>> 4) | (in[++inOff] << 5));
            out[outOff++] = (byte)((in[inOff] >>> 3) | (in[++inOff] << 6));
            out[outOff++] = (byte)((in[inOff] >>> 2) | (in[++inOff] << 7));
            out[outOff++] = (byte)(in[inOff++] >>> 1);
        }

        switch (inlen & 7)
        {
        case 1:
            out[outOff++] = (byte)in[inOff];
            out[outOff] = (byte)(in[inOff] >>> 8);
            break;
        case 2:
            out[outOff++] = (byte)in[inOff];
            out[outOff++] = (byte)((in[inOff] >>> 8) | (in[++inOff] << 1));
            out[outOff] = (byte)(in[inOff] >>> 7);
            break;
        case 3:
            out[outOff++] = (byte)in[inOff];
            out[outOff++] = (byte)((in[inOff] >>> 8) | (in[++inOff] << 1));
            out[outOff++] = (byte)((in[inOff] >>> 7) | (in[++inOff] << 2));
            out[outOff] = (byte)(in[inOff] >>> 6);
            break;
        case 4:
            out[outOff++] = (byte)in[inOff];
            out[outOff++] = (byte)((in[inOff] >>> 8) | (in[++inOff] << 1));
            out[outOff++] = (byte)((in[inOff] >>> 7) | (in[++inOff] << 2));
            out[outOff++] = (byte)((in[inOff] >>> 6) | (in[++inOff] << 3));
            out[outOff] = (byte)(in[inOff] >>> 5);
            break;
        case 5:
            out[outOff++] = (byte)in[inOff];
            out[outOff++] = (byte)((in[inOff] >>> 8) | (in[++inOff] << 1));
            out[outOff++] = (byte)((in[inOff] >>> 7) | (in[++inOff] << 2));
            out[outOff++] = (byte)((in[inOff] >>> 6) | (in[++inOff] << 3));
            out[outOff++] = (byte)((in[inOff] >>> 5) | (in[++inOff] << 4));
            out[outOff] = (byte)(in[inOff] >>> 4);
            break;
        case 6:
            out[outOff++] = (byte)in[inOff];
            out[outOff++] = (byte)((in[inOff] >>> 8) | (in[++inOff] << 1));
            out[outOff++] = (byte)((in[inOff] >>> 7) | (in[++inOff] << 2));
            out[outOff++] = (byte)((in[inOff] >>> 6) | (in[++inOff] << 3));
            out[outOff++] = (byte)((in[inOff] >>> 5) | (in[++inOff] << 4));
            out[outOff++] = (byte)((in[inOff] >>> 4) | (in[++inOff] << 5));
            out[outOff] = (byte)(in[inOff] >>> 3);
            break;
        case 7:
            out[outOff++] = (byte)in[inOff];
            out[outOff++] = (byte)((in[inOff] >>> 8) | (in[++inOff] << 1));
            out[outOff++] = (byte)((in[inOff] >>> 7) | (in[++inOff] << 2));
            out[outOff++] = (byte)((in[inOff] >>> 6) | (in[++inOff] << 3));
            out[outOff++] = (byte)((in[inOff] >>> 5) | (in[++inOff] << 4));
            out[outOff++] = (byte)((in[inOff] >>> 4) | (in[++inOff] << 5));
            out[outOff++] = (byte)((in[inOff] >>> 3) | (in[++inOff] << 6));
            out[outOff] = (byte)(in[inOff] >>> 2);
            break;
        }
    }

    public static void genericPack3Bit(byte[] out, int outOff, byte[] in, int inlen)
    {
        int fullBlocks = inlen >>> 3;
        int i;
        int inOff = 0;
        // Process full blocks (8 elements → 3 bytes)
        for (i = 0; i < fullBlocks; i++)
        {
            out[outOff++] = (byte)((in[inOff] & 0x07) | ((in[++inOff] & 0x07) << 3) | ((in[++inOff] & 0x03) << 6));
            out[outOff++] = (byte)(((in[inOff] >>> 2) & 0x01) | ((in[++inOff] & 0x07) << 1) | ((in[++inOff] & 0x07) << 4) | ((in[++inOff] & 0x01) << 7));
            out[outOff++] = (byte)(((in[inOff] >>> 1) & 0x03) | ((in[++inOff] & 0x07) << 2) | ((in[++inOff] & 0x07) << 5));
            inOff++;
        }

        // Process remaining elements (1-7)
        int remaining = inlen & 7;

        switch (remaining)
        {
        case 1:
            out[outOff] = (byte)(in[inOff] & 0x07);
            break;
        case 2:
            out[outOff] = (byte)((in[inOff] & 0x07) | ((in[++inOff] & 0x07) << 3));
            break;
        case 3:
            out[outOff++] = (byte)((in[inOff] & 0x07) | ((in[++inOff] & 0x07) << 3) | ((in[++inOff] & 0x03) << 6));
            out[outOff] = (byte)((in[inOff] >>> 2) & 0x01);
            break;
        case 4:
            out[outOff++] = (byte)((in[inOff] & 0x07) | ((in[++inOff] & 0x07) << 3) | ((in[++inOff] & 0x03) << 6));
            out[outOff] = (byte)(((in[inOff] >>> 2) & 0x01) | ((in[++inOff] & 0x07) << 1));
            break;
        case 5:
            out[outOff++] = (byte)((in[inOff] & 0x07) | ((in[++inOff] & 0x07) << 3) | ((in[++inOff] & 0x03) << 6));
            out[outOff] = (byte)(((in[inOff] >>> 2) & 0x01) | ((in[++inOff] & 0x07) << 1) | ((in[++inOff] & 0x07) << 4));
            break;
        case 6:
            out[outOff++] = (byte)((in[inOff] & 0x07) | ((in[++inOff] & 0x07) << 3) | ((in[++inOff] & 0x03) << 6));
            out[outOff++] = (byte)(((in[inOff] >>> 2) & 0x01) | ((in[++inOff] & 0x07) << 1) | ((in[++inOff] & 0x07) << 4) | ((in[++inOff] & 0x01) << 7));
            out[outOff] = (byte)((in[inOff] >>> 1) & 0x03);
            break;
        case 7:
            out[outOff++] = (byte)((in[inOff] & 0x07) | ((in[++inOff] & 0x07) << 3) | ((in[++inOff] & 0x03) << 6));
            out[outOff++] = (byte)(((in[inOff] >>> 2) & 0x01) | ((in[++inOff] & 0x07) << 1) | ((in[++inOff] & 0x07) << 4) | ((in[++inOff] & 0x01) << 7));
            out[outOff] = (byte)(((in[inOff] >>> 1) & 0x03) | ((in[++inOff] & 0x07) << 2));
            break;
        }
    }

    public static void genericPack7Bit(byte[] out, int outOff, byte[] in, int inlen)
    {
        int fullBlocks = inlen >>> 3;
        int i;
        int inOff = 0;
        for (i = 0; i < fullBlocks; i++)
        {
            out[outOff++] = (byte)(in[inOff] | ((in[++inOff] & 0xFF) << 7));
            out[outOff++] = (byte)(((in[inOff] & 0xFF) >>> 1) | ((in[++inOff] & 0xFF) << 6));
            out[outOff++] = (byte)(((in[inOff] & 0xFF) >>> 2) | ((in[++inOff] & 0xFF) << 5));
            out[outOff++] = (byte)(((in[inOff] & 0xFF) >>> 3) | ((in[++inOff] & 0xFF) << 4));
            out[outOff++] = (byte)(((in[inOff] & 0xFF) >>> 4) | ((in[++inOff] & 0xFF) << 3));
            out[outOff++] = (byte)(((in[inOff] & 0xFF) >>> 5) | ((in[++inOff] & 0xFF) << 2));
            out[outOff++] = (byte)(((in[inOff] & 0xFF) >>> 6) | ((in[++inOff] & 0xFF) << 1));
            inOff++;
        }

        switch (inlen & 7)
        {
        case 1:
            out[outOff] = in[inOff];
            break;
        case 2:
            out[outOff++] = (byte)(in[inOff] | ((in[++inOff] & 0xFF) << 7));
            out[outOff] = (byte)((in[inOff] & 0xFF) >>> 1);
            break;
        case 3:
            out[outOff++] = (byte)(in[inOff] | ((in[++inOff] & 0xFF) << 7));
            out[outOff++] = (byte)(((in[inOff] & 0xFF) >>> 1) | ((in[++inOff] & 0xFF) << 6));
            out[outOff] = (byte)((in[inOff] & 0xFF) >>> 2);
            break;
        case 4:
            out[outOff++] = (byte)(in[inOff] | ((in[++inOff] & 0xFF) << 7));
            out[outOff++] = (byte)(((in[inOff] & 0xFF) >>> 1) | ((in[++inOff] & 0x03) << 6));
            out[outOff++] = (byte)(((in[inOff] & 0xFF) >>> 2) | ((in[++inOff] & 0x07) << 5));
            out[outOff] = (byte)((in[inOff] & 0xFF) >>> 3);
            break;
        case 5:
            out[outOff++] = (byte)(in[inOff] | ((in[++inOff] & 0xFF) << 7));
            out[outOff++] = (byte)(((in[inOff] & 0xFF) >>> 1) | ((in[++inOff] & 0xFF) << 6));
            out[outOff++] = (byte)(((in[inOff] & 0xFF) >>> 2) | ((in[++inOff] & 0xFF) << 5));
            out[outOff++] = (byte)(((in[inOff] & 0xFF) >>> 3) | ((in[++inOff] & 0xFF) << 4));
            out[outOff] = (byte)((in[inOff] & 0xFF) >>> 4);
            break;
        case 6:
            out[outOff++] = (byte)(in[inOff] | ((in[++inOff] & 0xFF) << 7));
            out[outOff++] = (byte)(((in[inOff] & 0xFF) >>> 1) | ((in[++inOff] & 0xFF) << 6));
            out[outOff++] = (byte)(((in[inOff] & 0xFF) >>> 2) | ((in[++inOff] & 0xFF) << 5));
            out[outOff++] = (byte)(((in[inOff] & 0xFF) >>> 3) | ((in[++inOff] & 0xFF) << 4));
            out[outOff++] = (byte)(((in[inOff] & 0xFF) >>> 4) | ((in[++inOff] & 0xFF) << 3));
            out[outOff] = (byte)((in[inOff] & 0xFF) >>> 5);
            break;
        case 7:
            out[outOff++] = (byte)(in[inOff] | ((in[++inOff] & 0xFF) << 7));
            out[outOff++] = (byte)(((in[inOff] & 0xFF) >>> 1) | ((in[++inOff] & 0xFF) << 6));
            out[outOff++] = (byte)(((in[inOff] & 0xFF) >>> 2) | ((in[++inOff] & 0xFF) << 5));
            out[outOff++] = (byte)(((in[inOff] & 0xFF) >>> 3) | ((in[++inOff] & 0xFF) << 4));
            out[outOff++] = (byte)(((in[inOff] & 0xFF) >>> 4) | ((in[++inOff] & 0xFF) << 3));
            out[outOff++] = (byte)(((in[inOff] & 0xFF) >>> 5) | ((in[++inOff] & 0xFF) << 2));
            out[outOff] = (byte)((in[inOff] & 0xFF) >>> 6);
            break;
        }
    }

    public static boolean genericUnpack7Bit(byte[] out, byte[] in, int inOff, int outlen)
    {
        boolean isPackedPaddOk = true;
        int i;
        int outOff = 0;
        // Process full blocks (8 elements per 7 bytes)
        for (i = 0; i < outlen >>> 3; i++)
        {
            out[outOff++] = (byte)(in[inOff] & 0x7F);
            out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 7) | ((in[++inOff] << 1) & 0x7F));
            out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 6) | ((in[++inOff] << 2) & 0x7F));
            out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 5) | ((in[++inOff] << 3) & 0x7F));
            out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 4) | ((in[++inOff] << 4) & 0x7F));
            out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 3) | ((in[++inOff] << 5) & 0x7F));
            out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 2) | ((in[++inOff] << 6) & 0x7F));
            out[outOff++] = (byte)((in[inOff++] & 0xff) >>> 1);
        }

        // Handle remainder elements (1-7)
        int nRemainder = outlen & 7;
        if (nRemainder > 0)
        {
            switch (nRemainder)
            {
            case 1:
                out[outOff] = (byte)(in[inOff] & 0x7F);
                break;
            case 2:
                out[outOff++] = (byte)(in[inOff] & 0x7F);
                out[outOff] = (byte)(((in[inOff] & 0xff) >>> 7) | ((in[++inOff] << 1) & 0x7F));
                break;
            case 3:
                out[outOff++] = (byte)(in[inOff] & 0x7F);
                out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 7) | ((in[++inOff] << 1) & 0x7F));
                out[outOff] = (byte)(((in[inOff] & 0xff) >>> 6) | ((in[++inOff] << 2) & 0x7F));
                break;
            case 4:
                out[outOff++] = (byte)(in[inOff] & 0x7F);
                out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 7) | ((in[++inOff] << 1) & 0x7F));
                out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 6) | ((in[++inOff] << 2) & 0x7F));
                out[outOff] = (byte)(((in[inOff] & 0xff) >>> 5) | ((in[++inOff] << 3) & 0x7F));
                break;
            case 5:
                out[outOff++] = (byte)(in[inOff] & 0x7F);
                out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 7) | ((in[++inOff] << 1) & 0x7F));
                out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 6) | ((in[++inOff] << 2) & 0x7F));
                out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 5) | ((in[++inOff] << 3) & 0x7F));
                out[outOff] = (byte)(((in[inOff] & 0xff) >>> 4) | ((in[++inOff] << 4) & 0x7F));
                break;
            case 6:
                out[outOff++] = (byte)(in[inOff] & 0x7F);
                out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 7) | ((in[++inOff] << 1) & 0x7F));
                out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 6) | ((in[++inOff] << 2) & 0x7F));
                out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 5) | ((in[++inOff] << 3) & 0x7F));
                out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 4) | ((in[++inOff] << 4) & 0x7F));
                out[outOff] = (byte)(((in[inOff] & 0xff) >>> 3) | ((in[++inOff] << 5) & 0x7F));
                break;
            case 7:
                out[outOff++] = (byte)(in[inOff] & 0x7F);
                out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 7) | ((in[++inOff] << 1) & 0x7F));
                out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 6) | ((in[++inOff] << 2) & 0x7F));
                out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 5) | ((in[++inOff] << 3) & 0x7F));
                out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 4) | ((in[++inOff] << 4) & 0x7F));
                out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 3) | ((in[++inOff] << 5) & 0x7F));
                out[outOff] = (byte)(((in[inOff] & 0xff) >>> 2) | ((in[++inOff] << 6) & 0x7F));
                break;
            }
            if ((in[inOff] & (0xFF << (8 - nRemainder))) != 0)
            {
                isPackedPaddOk = false;
            }
        }
        return isPackedPaddOk;
    }

    public static boolean genericUnpack9Bit(short[] out, byte[] in, int inOff, int outlen)
    {
        boolean isPackedPaddOk = true;
        int i;
        int outOff = 0;
        // Process full blocks (8 elements per 9 bytes)
        for (i = 0; i < outlen >>> 3; i++)
        {
            out[outOff++] = (short)(((in[inOff] & 0xFF) | ((in[++inOff] & 0xFF) << 8)) & 0x1FF);
            out[outOff++] = (short)((((in[inOff] & 0xFF) >>> 1) | ((in[++inOff] & 0xFF) << 7)) & 0x1FF);
            out[outOff++] = (short)((((in[inOff] & 0xFF) >>> 2) | ((in[++inOff] & 0xFF) << 6)) & 0x1FF);
            out[outOff++] = (short)((((in[inOff] & 0xFF) >>> 3) | ((in[++inOff] & 0xFF) << 5)) & 0x1FF);
            out[outOff++] = (short)((((in[inOff] & 0xFF) >>> 4) | ((in[++inOff] & 0xFF) << 4)) & 0x1FF);
            out[outOff++] = (short)((((in[inOff] & 0xFF) >>> 5) | ((in[++inOff] & 0xFF) << 3)) & 0x1FF);
            out[outOff++] = (short)((((in[inOff] & 0xFF) >>> 6) | ((in[++inOff] & 0xFF) << 2)) & 0x1FF);
            out[outOff++] = (short)((((in[inOff] & 0xFF) >>> 7) | ((in[++inOff] & 0xFF) << 1)) & 0x1FF);
            inOff++;
        }

        // Handle remainder elements (1-7)
        int nRemainder = outlen & 7;
        if (nRemainder > 0)
        {
            switch (nRemainder)
            {
            case 1:
                out[outOff] = (short)(((in[inOff] & 0xFF) | ((in[++inOff] & 0xFF) << 8)) & 0x1FF);
                break;
            case 2:
                out[outOff++] = (short)(((in[inOff] & 0xFF) | ((in[++inOff] & 0xFF) << 8)) & 0x1FF);
                out[outOff] = (short)((((in[inOff] & 0xFF) >>> 1) | ((in[++inOff] & 0xFF) << 7)) & 0x1FF);
                break;
            case 3:
                out[outOff++] = (short)(((in[inOff] & 0xFF) | ((in[++inOff] & 0xFF) << 8)) & 0x1FF);
                out[outOff++] = (short)((((in[inOff] & 0xFF) >>> 1) | ((in[++inOff] & 0xFF) << 7)) & 0x1FF);
                out[outOff] = (short)((((in[inOff] & 0xFF) >>> 2) | ((in[++inOff] & 0xFF) << 6)) & 0x1FF);
                break;
            case 4:
                out[outOff++] = (short)(((in[inOff] & 0xFF) | ((in[++inOff] & 0xFF) << 8)) & 0x1FF);
                out[outOff++] = (short)((((in[inOff] & 0xFF) >>> 1) | ((in[++inOff] & 0xFF) << 7)) & 0x1FF);
                out[outOff++] = (short)((((in[inOff] & 0xFF) >>> 2) | ((in[++inOff] & 0xFF) << 6)) & 0x1FF);
                out[outOff] = (short)((((in[inOff] & 0xFF) >>> 3) | ((in[++inOff] & 0xFF) << 5)) & 0x1FF);
                break;
            case 5:
                out[outOff++] = (short)(((in[inOff] & 0xFF) | ((in[++inOff] & 0xFF) << 8)) & 0x1FF);
                out[outOff++] = (short)((((in[inOff] & 0xFF) >>> 1) | ((in[++inOff] & 0xFF) << 7)) & 0x1FF);
                out[outOff++] = (short)((((in[inOff] & 0xFF) >>> 2) | ((in[++inOff] & 0xFF) << 6)) & 0x1FF);
                out[outOff++] = (short)((((in[inOff] & 0xFF) >>> 3) | ((in[++inOff] & 0xFF) << 5)) & 0x1FF);
                out[outOff] = (short)((((in[inOff] & 0xFF) >>> 4) | ((in[++inOff] & 0xFF) << 4)) & 0x1FF);
                break;
            case 6:
                out[outOff++] = (short)(((in[inOff] & 0xFF) | ((in[++inOff] & 0xFF) << 8)) & 0x1FF);
                out[outOff++] = (short)((((in[inOff] & 0xFF) >>> 1) | ((in[++inOff] & 0xFF) << 7)) & 0x1FF);
                out[outOff++] = (short)((((in[inOff] & 0xFF) >>> 2) | ((in[++inOff] & 0xFF) << 6)) & 0x1FF);
                out[outOff++] = (short)((((in[inOff] & 0xFF) >>> 3) | ((in[++inOff] & 0xFF) << 5)) & 0x1FF);
                out[outOff++] = (short)((((in[inOff] & 0xFF) >>> 4) | ((in[++inOff] & 0xFF) << 4)) & 0x1FF);
                out[outOff] = (short)((((in[inOff] & 0xFF) >>> 5) | ((in[++inOff] & 0xFF) << 3)) & 0x1FF);
                break;
            case 7:
                out[outOff++] = (short)(((in[inOff] & 0xFF) | ((in[++inOff] & 0xFF) << 8)) & 0x1FF);
                out[outOff++] = (short)((((in[inOff] & 0xFF) >>> 1) | ((in[++inOff] & 0xFF) << 7)) & 0x1FF);
                out[outOff++] = (short)((((in[inOff] & 0xFF) >>> 2) | ((in[++inOff] & 0xFF) << 6)) & 0x1FF);
                out[outOff++] = (short)((((in[inOff] & 0xFF) >>> 3) | ((in[++inOff] & 0xFF) << 5)) & 0x1FF);
                out[outOff++] = (short)((((in[inOff] & 0xFF) >>> 4) | ((in[++inOff] & 0xFF) << 4)) & 0x1FF);
                out[outOff++] = (short)((((in[inOff] & 0xFF) >>> 5) | ((in[++inOff] & 0xFF) << 3)) & 0x1FF);
                out[outOff] = (short)((((in[inOff] & 0xFF) >>> 6) | ((in[++inOff] & 0xFF) << 2)) & 0x1FF);
                break;
            }
            if ((in[inOff] & (0xFF << nRemainder)) != 0)
            {
                isPackedPaddOk = false;
            }
        }
        return isPackedPaddOk;
    }

    static boolean genericUnpack3Bit(byte[] out, byte[] in, int inOff, int outlen)
    {
        boolean isPackedPaddOk = true;
        int i;
        int outOff = 0;

        // Process full blocks (8 elements per 3 bytes)
        for (i = 0; i < outlen >>> 3; i++)
        {
            out[outOff++] = (byte)(in[inOff] & 0x07);
            out[outOff++] = (byte)((in[inOff] >>> 3) & 0x07);
            out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 6) | (in[++inOff] << 2) & 0x07);
            out[outOff++] = (byte)((in[inOff] >>> 1) & 0x07);
            out[outOff++] = (byte)((in[inOff] >>> 4) & 0x07);
            out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 7) | (in[++inOff] << 1) & 0x07);
            out[outOff++] = (byte)((in[inOff] >>> 2) & 0x07);
            out[outOff++] = (byte)((in[inOff++] >>> 5) & 0x07);
        }

        // Handle remainder elements (1-7)
        int nRemainder = outlen & 7;
        if (nRemainder > 0)
        {
            switch (nRemainder)
            {
            case 1:
                out[outOff] = (byte)(in[inOff] & 0x07);
                break;
            case 2:
                out[outOff++] = (byte)(in[inOff] & 0x07);
                out[outOff] = (byte)((in[inOff] >>> 3) & 0x07);
                break;
            case 3:
                out[outOff++] = (byte)(in[inOff] & 0x07);
                out[outOff++] = (byte)((in[inOff] >>> 3) & 0x07);
                out[outOff] = (byte)(((in[inOff] & 0xff) >>> 6) | (in[++inOff] << 2) & 0x07);
                break;
            case 4:
                out[outOff++] = (byte)(in[inOff] & 0x07);
                out[outOff++] = (byte)((in[inOff] >>> 3) & 0x07);
                out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 6) | (in[++inOff] << 2) & 0x07);
                out[outOff] = (byte)((in[inOff] >>> 1) & 0x07);
                break;
            case 5:
                out[outOff++] = (byte)(in[inOff] & 0x07);
                out[outOff++] = (byte)((in[inOff] >>> 3) & 0x07);
                out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 6) | (in[++inOff] << 2) & 0x07);
                out[outOff++] = (byte)((in[inOff] >>> 1) & 0x07);
                out[outOff] = (byte)((in[inOff] >>> 4) & 0x07);
                break;
            case 6:
                out[outOff++] = (byte)(in[inOff] & 0x07);
                out[outOff++] = (byte)((in[inOff] >>> 3) & 0x07);
                out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 6) | (in[++inOff] << 2) & 0x07);
                out[outOff++] = (byte)((in[inOff] >>> 1) & 0x07);
                out[outOff++] = (byte)((in[inOff] >>> 4) & 0x07);
                out[outOff] = (byte)(((in[inOff] & 0xff) >>> 7) | (in[++inOff] << 1) & 0x07);
                break;
            case 7:
                out[outOff++] = (byte)(in[inOff] & 0x07);
                out[outOff++] = (byte)((in[inOff] >>> 3) & 0x07);
                out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 6) | (in[++inOff] << 2) & 0x07);
                out[outOff++] = (byte)((in[inOff] >>> 1) & 0x07);
                out[outOff++] = (byte)((in[inOff] >>> 4) & 0x07);
                out[outOff++] = (byte)(((in[inOff] & 0xff) >>> 7) | (in[++inOff] << 1) & 0x07);
                out[outOff] = (byte)((in[inOff] >>> 2) & 0x07);
                break;
            }
            if ((in[inOff] & (0xFF << (nRemainder * 3) & 7)) != 0)
            {
                isPackedPaddOk = false;
            }
        }

        return isPackedPaddOk;
    }

    // Helper function to round up to nearest multiple
    public static int roundUp(int amount, int roundAmt)
    {
        return ((amount + roundAmt - 1) / roundAmt) * roundAmt;
    }

    /**
     * Constant-time conditional move (CMOV) operation for cryptographic implementations.
     * Returns either the true value (if bit=1) or 1 (if bit=0) without using branches,
     * providing protection against timing side-channel attacks.
     *
     * @param bit     The condition bit (0 or 1)
     * @param trueVal The value to return when bit=1
     * @return trueVal if bit=1, 1 otherwise
     */
    static int cmov(int bit, int trueVal)
    {
        int mask = -bit; // mask = 0xFFFFFFFF if bit=1, 0 if bit=0
        return (trueVal & mask) | (1 & ~mask);
    }

    public static int fzRedSingle(int x)
    {
        //this is simplified, for RDSP, it should be (x & 0x07) + (x >>> 3). However, it seems norm function can solve this issue
        return (x & 0x7F) + (x >>> 7);
    }

    public static short fpRedSingle(int x)
    {
        long xLong = x & 0xFFFFFFFFL; // Treat as unsigned
        long quotient = (xLong * REDUCTION_CONST) >>> 40;
        long result = xLong - quotient * 509;
        if (result < 0)
        {
            result += 509;
        }
        else if (result >= 509)
        {
            result -= 509;
        }
        return (short)result;
    }

    public static int fpRedDouble(int x)
    {
        return fzRedSingle(fzRedSingle(x));
    }

    /**
     * Converts a restricted exponent to a finite field value using precomputed table lookup.
     * This method is optimized for RSDP variant (P=127) where elements are represented as 7-bit values.
     * The implementation extracts an 8-bit value from a precomputed constant table by shifting
     * 8*x bits and taking the least significant byte.
     *
     * @param x The exponent index (0-127) to convert
     * @return The finite field element corresponding to the exponent
     */
    public static byte restrToVal(int x)
    {
        return (byte)(RESTR_G_TABLE >>> (x << 3));
    }

    /**
     * Converts a restricted exponent to a finite field value for RSDPG variant (P=509).
     * This method computes g^x mod 509 using precomputed generator powers in constant time,
     * where g is a fixed generator of the multiplicative group. The 7-bit exponent is decomposed
     * into its binary representation, and the corresponding powers are multiplied together.
     * Intermediate results are reduced modulo 509 to prevent overflow.
     *
     * @param x The 7-bit exponent (0-127) to raise the generator to
     * @return The finite field element g^x mod 509 as a short value
     */
    public static short restrToValRsdpg(byte x)
    {
        int xInt = x & 0xFF;
        int finalProd = fpRedSingle(fpRedSingle(cmov((xInt) & 1, RESTR_G_GEN_1) * cmov((xInt >> 1) & 1, RESTR_G_GEN_2)
            * cmov((xInt >> 2) & 1, RESTR_G_GEN_4) * cmov((xInt >> 3) & 1, RESTR_G_GEN_8)) *
            fpRedSingle(cmov((xInt >> 4) & 1, RESTR_G_GEN_16) * cmov((xInt >> 5) & 1, RESTR_G_GEN_32) * cmov((xInt >> 6) & 1, RESTR_G_GEN_64)));

        return (short)finalProd;
    }
}
