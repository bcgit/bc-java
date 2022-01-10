package org.bouncycastle.pqc.crypto.cmce;

class BENES13
    extends BENES
{
    public BENES13(int n, int t, int m)
    {
        super(n, t, m);
    }

    /* middle layers of the benes network */
    static void layer_in(long[] data, long[] bits, int lgs)
    {
        int i, j, s;
        int bit_ptr = 0;
        long d;

        s = 1 << lgs;

        for (i = 0; i < 64; i += s * 2)
        {
            for (j = i; j < i + s; j++)
            {

                d = (data[j + 0] ^ data[j + s]);
                d &= bits[bit_ptr++];
                data[j + 0] ^= d;
                data[j + s] ^= d;

                d = (data[64 + j + 0] ^ data[64 + j + s]);
                d &= bits[bit_ptr++];
                data[64 + j + 0] ^= d;
                data[64 + j + s] ^= d;
            }
        }
    }

    /* first and last layers of the benes network */
    static void layer_ex(long[] data, long[] bits, int lgs)
    {
        int i, j, s;
        int bit_ptr = 0;

        long d;

        s = 1 << lgs;

        for (i = 0; i < 128; i += s * 2)
        {
            for (j = i; j < i + s; j++)
            {

                d = (data[j + 0] ^ data[j + s]);
                d &= bits[bit_ptr++];
                data[j + 0] ^= d;
                data[j + s] ^= d;
            }
        }
    }

    /* input: r, sequence of bits to be permuted */
    /*        bits, condition bits of the Benes network */
    /*        rev, 0 for normal application; !0 for inverse */
    /* output: r, permuted bits */
    void apply_benes(byte[] r, byte[] bits, int rev)
    {
        int i, iter, inc;

        int r_ptr = 0;
        int bits_ptr = 0;

//        long[] r_int_v_0 = new long[64];
//        long[] r_int_v_1 = new long[64];
//        long[] r_int_h_0 = new long[64];
//        long[] r_int_h_1 = new long[64];
        long[] r_int_v = new long[128];
        long[] r_int_h = new long[128];
        long[] b_int_v = new long[64];
        long[] b_int_h = new long[64];

        //

        if (rev == 0)
        {
            bits_ptr = SYS_T * 2 + 40;
            inc = 0;
        }
        else

        {
            bits_ptr = SYS_T * 2 + 40 + 12288;
            inc = -1024;
        }

        for (i = 0; i < 64; i++)//TODO use load8
        {
            r_int_v[i + 0] = Utils.load8(r, r_ptr + i * 16 + 0);
            r_int_v[i + 64] = Utils.load8(r, r_ptr + i * 16 + 8);
        }

        transpose_64x64(r_int_h, r_int_v, 0);
        transpose_64x64(r_int_h, r_int_v, 64);

        for (iter = 0; iter <= 6; iter++)
        {
            for (i = 0; i < 64; i++)//TODO use load8
            {
                b_int_v[i] = Utils.load8(bits, bits_ptr);
                bits_ptr += 8;
            }

            bits_ptr += inc;

            transpose_64x64(b_int_h, b_int_v);

            layer_ex(r_int_h, b_int_h, iter);
        }

        transpose_64x64(r_int_v, r_int_h, 0);
        transpose_64x64(r_int_v, r_int_h, 64);

        for (iter = 0; iter <= 5; iter++)
        {
            for (i = 0; i < 64; i++)//TODO use load8
            {
                b_int_v[i] = Utils.load8(bits, bits_ptr);
                bits_ptr += 8;
            }
            bits_ptr += inc;

            layer_in(r_int_v, b_int_v, iter);
        }

        for (iter = 4; iter >= 0; iter--)
        {
            for (i = 0; i < 64; i++)//TODO use load8
            {
                b_int_v[i] = Utils.load8(bits, bits_ptr);
                bits_ptr += 8;
            }
            bits_ptr += inc;

            layer_in(r_int_v, b_int_v, iter);
        }

        transpose_64x64(r_int_h, r_int_v, 0);
        transpose_64x64(r_int_h, r_int_v, 64);

        for (iter = 6; iter >= 0; iter--)
        {
            for (i = 0; i < 64; i++)//TODO use load8
            {
                b_int_v[i] = Utils.load8(bits, bits_ptr);
                bits_ptr += 8;
            }

            bits_ptr += inc;

            transpose_64x64(b_int_h, b_int_v);

            layer_ex(r_int_h, b_int_h, iter);
        }

        transpose_64x64(r_int_v, r_int_h, 0);
        transpose_64x64(r_int_v, r_int_h, 64);

        for (i = 0; i < 64; i++)//TODO use store8
        {
            Utils.store8(r, r_ptr + i * 16 + 0, r_int_v[0 + i]);
            Utils.store8(r, r_ptr + i * 16 + 8, r_int_v[64 + i]);
        }
    }

    /* input: condition bits c */
    /* output: support s */
    public void support_gen(short[] s, byte[] c)
    {
        short a;
        int i, j;
        byte[][] L = new byte[GFBITS][(1 << GFBITS) / 8];

        for (i = 0; i < GFBITS; i++)
        {
            for (j = 0; j < (1 << GFBITS) / 8; j++)
            {
                L[i][j] = 0;
            }
        }
        for (i = 0; i < (1 << GFBITS); i++)
        {
            a = Utils.bitrev((short)i, GFBITS);

            for (j = 0; j < GFBITS; j++)
            {
                L[j][i / 8] |= ((a >> j) & 1) << (i % 8);
            }
        }

        for (j = 0; j < GFBITS; j++)
        {
            apply_benes(L[j], c, 0);
        }
        for (i = 0; i < SYS_N; i++)
        {
            s[i] = 0;
            for (j = GFBITS - 1; j >= 0; j--)
            {
                s[i] <<= 1;
                s[i] |= (L[j][i / 8] >> (i % 8)) & 1;
            }
        }
    }

}
