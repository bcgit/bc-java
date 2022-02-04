package org.bouncycastle.pqc.crypto.cmce;

import org.bouncycastle.util.Pack;

class Utils
{
    //working
    //field: 3373 3828 2097 962 3204 2740 2724 50 1397 1050 2261 4020 3204 1298 166 697 3967 935 1349 3845 2674 2338 2708 2915 2348 2401 1436 3875 202 1248 3190 312 1087 1820 883 3313 1313 878 1455 2878 1477 2067 309 2219 2909 3665 3171 2419 3449 2562 1093 1107 6 847 859 2999 2103 3201 3519 3424 195 148 588 3745
    // ef4
    //
    //load
    //field: 3373 4084 2097 4034 3972 4020 4004 50 1397 1050 4053 4020 3972 1298 4006 4025 3967 4007 1349 3845 2674 2338 3988 2915 2348 2401 3996 3875 4042 4064 3190 312 1087 1820 883 4081 1313 878 4015 2878 4037 2067 309 4011 2909 3665 3171 2419 3449 2562 1093 1107 6 847 859 4023 2103 3969 4031 3424 4035 3988 588 4001
    static void store_gf(byte[] dest, int offset, short a)
    {
        dest[offset + 0] = (byte) (a & 0xFF);
        dest[offset + 1] = (byte) (a >> 8);
    }
    static short load_gf(byte[] src, int offset, int gfmask)
    {
//        byte[] temp = Arrays.copyOfRange(src, offset, offset + 2);
//        temp[1] &= 0xf; // java signed bits calculation
        return (short) (Pack.littleEndianToShort(src, offset) & gfmask);

//        short a;
//        a = src[offset + 1];
//        a <<= 8;
//        a |= src[offset];
//        return (short) a; //(a & gfmask);
    }
    static int load4(byte[] in, int offset)
    {
        //TODO make this without using Pack
        return Pack.littleEndianToInt(in, offset);
//        int i;
//        int ret = in[3+offset];
//
//        for (i = 2; i >= 0; i--)
//        {
//            ret <<= 8;
//            ret |= in[i+offset];
//        }
//        return ret;
    }
    static void store8(byte[] out, int offset, long in)
    {
        out[offset + 0] = (byte) ((in >> 0x00) & 0xFF);
        out[offset + 1] = (byte) ((in >> 0x08) & 0xFF);
        out[offset + 2] = (byte) ((in >> 0x10) & 0xFF);
        out[offset + 3] = (byte) ((in >> 0x18) & 0xFF);
        out[offset + 4] = (byte) ((in >> 0x20) & 0xFF);
        out[offset + 5] = (byte) ((in >> 0x28) & 0xFF);
        out[offset + 6] = (byte) ((in >> 0x30) & 0xFF);
        out[offset + 7] = (byte) ((in >> 0x38) & 0xFF);
    }
    static long load8(byte[] in, int offset)
    {
        //TODO make this without using Pack
        return Pack.littleEndianToLong(in, offset);
//        int i;
//        long ret = in[7];
//
//        for (i = 6; i >= 0; i--)
//        {
//            ret <<= 8;
//            ret |= in[i];
//        }
//
//        return ret;
    }

    static short bitrev(short a, int GFBITS)
    {
        a = (short)( ((a & 0x00FF) << 8) | ((a & 0xFF00) >> 8));
        a = (short)( ((a & 0x0F0F) << 4) | ((a & 0xF0F0) >> 4));
        a = (short)( ((a & 0x3333) << 2) | ((a & 0xCCCC) >> 2));
        a = (short)( ((a & 0x5555) << 1) | ((a & 0xAAAA) >> 1));
        if (GFBITS == 12)
            return (short) (a >> 4);
        return (short) (a >> 3);
    }



}
