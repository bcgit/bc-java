package org.bouncycastle.pqc.crypto.cmce;

class GF13
    extends GF
{
    public GF13(int gfbits)
    {
        super(gfbits);
    }

    @Override
    protected short gf_mul(short in0, short in1)
    {
        int i;

        long tmp;
        long t0;
        long t1;
        long t;

        t0 = in0;
        t1 = in1;

        tmp = t0 * (t1 & 1);

        for (i = 1; i < GFBITS; i++)
            tmp ^= (t0 * (t1 & (1 << i)));

        //

        t = tmp & 0x1FF0000L;
        tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

        t = tmp & 0x000E000L;
        tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

        return (short) (tmp & GFMASK);
    }

    /* input: field element in */
    /* return: (in^2)^2 */
    protected short gf_sq2(short in)
    {
        int i;

        long[] B = {0x1111111111111111L,
                    0x0303030303030303L,
                    0x000F000F000F000FL,
                    0x000000FF000000FFL};

        long[] M = {0x0001FF0000000000L,
                    0x000000FF80000000L,
                    0x000000007FC00000L,
                    0x00000000003FE000L};

        long x = in;
        long t;

        x = (x | (x << 24)) & B[3];
        x = (x | (x << 12)) & B[2];
        x = (x | (x << 6)) & B[1];
        x = (x | (x << 3)) & B[0];

        for (i = 0; i < 4; i++)
        {
            t = x & M[i];
            x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
        }

        return (short) (x & GFMASK);
    }

    /* input: field element in, m */
    /* return: (in^2)*m */
    private short gf_sqmul(short in, short m)
    {
        int i;

        long x;
        long t0;
        long t1;
        long t;

        long[] M = {0x0000001FF0000000L,
                    0x000000000FF80000L,
                    0x000000000007E000L};

        t0 = in;
        t1 = m;

        x = (t1 << 6) * (t0 & (1 << 6));

        t0 ^= (t0 << 7);

        x ^= (t1 * (t0 & (0x04001)));
        x ^= (t1 * (t0 & (0x08002))) << 1;
        x ^= (t1 * (t0 & (0x10004))) << 2;
        x ^= (t1 * (t0 & (0x20008))) << 3;
        x ^= (t1 * (t0 & (0x40010))) << 4;
        x ^= (t1 * (t0 & (0x80020))) << 5;

        for (i = 0; i < 3; i++)
        {
            t = x & M[i];
            x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
        }

        return (short) (x & GFMASK);
    }

    /* input: field element in, m */
    /* return: ((in^2)^2)*m */
    private short gf_sq2mul(short in, short m)
    {
        int i;

        long x;
        long t0;
        long t1;
        long t;

        long[] M = {0x1FF0000000000000L,
                    0x000FF80000000000L,
                    0x000007FC00000000L,
                    0x00000003FE000000L,
                    0x0000000001FE0000L,
                    0x000000000001E000L};

        t0 = in;
        t1 = m;

        x = (t1 << 18) * (t0 & (1 << 6));

        t0 ^= (t0 << 21);

        x ^= (t1 * (t0 & (0x010000001L)));
        x ^= (t1 * (t0 & (0x020000002L))) << 3;
        x ^= (t1 * (t0 & (0x040000004L))) << 6;
        x ^= (t1 * (t0 & (0x080000008L))) << 9;
        x ^= (t1 * (t0 & (0x100000010L))) << 12;
        x ^= (t1 * (t0 & (0x200000020L))) << 15;

        for (i = 0; i < 6; i++)
        {
            t = x & M[i];
            x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
        }

        return (short) (x & GFMASK);
    }

    /* input: field element den, num */
    /* return: (num/den) */
    @Override
    protected short gf_frac(short den, short num)
    {
        short tmp_11;
        short tmp_1111;
        short out;

        tmp_11 = gf_sqmul(den, den); // ^11
        tmp_1111 = gf_sq2mul(tmp_11, tmp_11); // ^1111
        out = gf_sq2(tmp_1111);
        out = gf_sq2mul(out, tmp_1111); // ^11111111
        out = gf_sq2(out);
        out = gf_sq2mul(out, tmp_1111); // ^111111111111

        return gf_sqmul(out, num); // ^1111111111110 = ^-1
    }

    @Override
    protected short gf_inv(short den)
    {
        return gf_frac(den, ((short) 1));
    }

    


}
