package org.bouncycastle.pqc.crypto.sphincsplus;

class HarakaSXof
    extends HarakaSBase
{
    public String getAlgorithmName()
    {
        return "Haraka-S";
    }

    public HarakaSXof(byte[] pkSeed)
    {
        byte[] buf = new byte[640];
        update(pkSeed, 0, pkSeed.length);
        doFinal(buf, 0, buf.length);
        haraka512_rc = new long[10][8];
        haraka256_rc = new int[10][8];
        for (int i = 0; i < 10; ++i)
        {
            interleaveConstant32(haraka256_rc[i], buf, i << 5);
            interleaveConstant(haraka512_rc[i], buf, i << 6);
        }
    }

    public void update(byte[] input, int inOff, int len)
    {
        int i = inOff, j, loop = (len + off) >> 5;
        for (j = 0; j < loop; ++j)
        {
            while (off < 32)
            {
                buffer[off++] ^= input[i++];
            }
            haraka512Perm(buffer);
            off = 0;
        }
        while (i < inOff + len)
        {
            buffer[off++] ^= input[i++];
        }
    }

    public void update(byte input)
    {
        buffer[off++] ^= input;
        if (off == 32)
        {
            haraka512Perm(buffer);
            off = 0;
        }
    }

    public int doFinal(byte[] out, int outOff, int len)
    {
        int outLen = len;

        //Finalize
        buffer[off] ^= 0x1F;
        buffer[31] ^= 128;

        //Squeeze
        while (len >= 32)
        {
            haraka512Perm(buffer);
            System.arraycopy(buffer, 0, out, outOff, 32);
            outOff += 32;
            len -= 32;
        }
        if (len > 0)
        {
            haraka512Perm(buffer);
            System.arraycopy(buffer, 0, out, outOff, len);
        }

        reset();

        return outLen;
    }
}
