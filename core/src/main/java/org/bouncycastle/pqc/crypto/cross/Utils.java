package org.bouncycastle.pqc.crypto.cross;

class Utils
{
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
            out[outOff + 1] = (byte)(((in[inOff] >>> 2) & 0x01) | ((in[++inOff] & 0x07) << 1) | ((in[++inOff] & 0x07) << 4));
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

    public static boolean genericUnpack7Bit(byte[] out, byte[] in, int outlen, int inlen)
    {
        boolean isPackedPaddOk = true;
        int i;
        int inOff = 0, outOff = 0;
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
            // Check padding bits in last byte
            int unusedBits = 8 - nRemainder;
            int lastByte = in[inlen - 1];
            if ((lastByte & (0xFF << unusedBits)) != 0)
            {
                isPackedPaddOk = false;
            }
        }
        return isPackedPaddOk;
    }

    public static boolean genericUnpack9Bit(short[] out, byte[] in, int outlen, int inlen)
    {
        boolean isPackedPaddOk = true;
        int i;
        int inOff = 0, outOff = 0;
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
            // Check padding bits in last byte
            int lastByte = in[inlen - 1];
            if ((lastByte & (0xFF << nRemainder)) != 0)
            {
                isPackedPaddOk = false;
            }
        }
        return isPackedPaddOk;
    }

    static boolean genericUnpack3Bit(byte[] out, byte[] in, int outlen)
    {
        boolean isPackedPaddOk = true;
        int i;
        int inOff = 0, outOff = 0;

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

            // Check padding bits in last byte
            int lastByte = in[inOff];
            int paddingMask = 0xFF << (nRemainder * 3) & 7;

            if ((lastByte & paddingMask) != 0)
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
}
