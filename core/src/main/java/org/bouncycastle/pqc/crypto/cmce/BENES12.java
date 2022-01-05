package org.bouncycastle.pqc.crypto.cmce;

class BENES12
    extends BENES
{
    public BENES12(int n, int t, int m)
    {
        super(n, t, m);
    }

    /* one layer of the benes network */
    static void layerBenes(long[] data, long[] bits, int lgs)
    {
        int i, j, s;
        int bit_ptr = 0;

        long d;

        s = 1 << lgs;

        for (i = 0; i < 64; i += s*2)
        {
            for (j = i; j < i+s; j++)
            {
                d = (data[j+0] ^ data[j+s]);
                d &= bits[bit_ptr++];
                data[j+0] ^= d;
                data[j+s] ^= d;
            }
        }
    }

    private void apply_benes(byte[] r, byte[] bits, int rev)
    {
        int i;

        int cond_ptr;
        int inc, low;

        long[] bs = new long[64];
        long[] cond = new long[64];

        //
        for (i = 0; i < 64; i++)//DONE use Utils load8
        {
//            bs[i] = Pack.littleEndianToLong(r, i*8);
            bs[i] = Utils.load8(r, i*8);
        }

        if (rev == 0)
        {
            inc = 256;
            cond_ptr = SYS_T*2+40;
        }
        else
        {
            inc = -256;
            cond_ptr = SYS_T*2+40 + (2*GFBITS-2)*256;
        }

        //

        transpose_64x64(bs, bs);
        for (low = 0; low <= 5; low++)
        {
            for (i = 0; i < 64; i++)//DONE use Utils load4
            {
                cond[i] = Utils.load4(bits, cond_ptr + i*4);
//                cond[i] = Pack.littleEndianToInt(bits, cond_ptr + i*4) & 0xffffffffL;
            }

            transpose_64x64(cond, cond);
            layerBenes(bs, cond, low);

            cond_ptr += inc;
        }

        transpose_64x64(bs, bs);

        for (low = 0; low <= 5; low++)
        {
            for (i = 0; i < 32; i++)//DONE use Utils load8
            {
                cond[i] = Utils.load8(bits, cond_ptr + i*8);
//                cond[i] = Pack.littleEndianToLong(bits, cond_ptr + i*8);
            }
            layerBenes(bs, cond, low);
            cond_ptr += inc;
        }
        for (low = 4; low >= 0; low--)
        {
            for (i = 0; i < 32; i++)//DONE use Utils load8
            {
                cond[i] = Utils.load8(bits, cond_ptr + i*8);
//                cond[i] = Pack.littleEndianToLong(bits, cond_ptr + i*8);
            }

            layerBenes(bs, cond, low);
            cond_ptr += inc;
        }

        transpose_64x64(bs, bs);

        for (low = 5; low >= 0; low--)
        {
            for (i = 0; i < 64; i++)//DONE use Utils load4
            {
                cond[i] = Utils.load4(bits, cond_ptr + i*4);
//                cond[i] = Pack.littleEndianToInt(bits, cond_ptr + i*4) & 0xffffffffL;
            }

            transpose_64x64(cond, cond);
            layerBenes(bs, cond, low);
            cond_ptr += inc;
        }

        transpose_64x64(bs, bs);

        //
        for (i = 0; i < 64; i++)//DONE use Utils store8
        {
            Utils.store8(r,i*8, bs[i]);
//            byte[] temp = Pack.longToLittleEndian(bs[i]);
//            System.arraycopy(temp, 0, r, i * 8, 8);

        }
    }

    // from benes network
    public void support_gen(short[] s, byte[] c)
    {
        short a;
        byte[][] L = new byte[GFBITS][(1 << GFBITS)/8];

        for(int i = 0; i < GFBITS; i++)
        {
            for (int j = 0; j < (1 << GFBITS)/8; j++)
            {
                L[i][j] = 0;
            }
        }

        for(int i = 0; i < (1 << GFBITS); i++)//DONE change to Utils bitrev
        {
            a = Utils.bitrev((short) i, GFBITS);
//            a = (short) (Utils.rev_bit((short) i) & 0x0fff); // casting to gf

            for(int j = 0; j < GFBITS; j++)
            {
                L[j][i/8] |=((a >> j) & 1) << (i%8);
            }
        }

        for(int j = 0; j < GFBITS; j++)
        {
            apply_benes(L[j], c, 0);
        }

        for (int i = 0; i < SYS_N; i++)
        {
            s[i] = 0;
            for (int j = GFBITS-1; j >= 0; j--)
            {
                s[i] <<= 1;
                s[i] |= (L[j][i/8] >> (i%8)) & 1;

            }
        }
    }

}
