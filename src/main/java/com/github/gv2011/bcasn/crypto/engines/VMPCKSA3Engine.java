package com.github.gv2011.bcasn.crypto.engines;

public class VMPCKSA3Engine extends VMPCEngine
{
    public String getAlgorithmName()
    {
        return "VMPC-KSA3";
    }

    protected void initKey(byte[] keyBytes, byte[] ivBytes)
    {
        s = 0;
        P = new byte[256];
        for (int i = 0; i < 256; i++)
        {
            P[i] = (byte) i;
        }

        for (int m = 0; m < 768; m++)
        {
            s = P[(s + P[m & 0xff] + keyBytes[m % keyBytes.length]) & 0xff];
            byte temp = P[m & 0xff];
            P[m & 0xff] = P[s & 0xff];
            P[s & 0xff] = temp;
        }

        for (int m = 0; m < 768; m++)
        {
            s = P[(s + P[m & 0xff] + ivBytes[m % ivBytes.length]) & 0xff];
            byte temp = P[m & 0xff];
            P[m & 0xff] = P[s & 0xff];
            P[s & 0xff] = temp;
        }

        for (int m = 0; m < 768; m++)
        {
            s = P[(s + P[m & 0xff] + keyBytes[m % keyBytes.length]) & 0xff];
            byte temp = P[m & 0xff];
            P[m & 0xff] = P[s & 0xff];
            P[s & 0xff] = temp;
        }

        n = 0;
    }
}
