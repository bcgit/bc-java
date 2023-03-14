package org.bouncycastle.pqc.crypto.cmce;

import org.bouncycastle.math.raw.Interleave;

final class GF13
    extends GF
{
    GF13()
    {
    }

    protected void gf_mul_poly(int length, int[] poly, short[] out, short[] left, short[] right, int[] temp)
    {
        temp[0] = gf_mul_ext(left[0], right[0]);

        for (int i = 1; i < length; i++)
        {
            temp[i + i - 1] = 0;

            short left_i = left[i];
            short right_i = right[i];

            for (int j = 0; j < i; j++)
            {
                temp[i + j] ^= gf_mul_ext_par(left_i, right[j], left[j], right_i);
            }

            temp[i + i] = gf_mul_ext(left_i, right_i);
        }

        for (int i = (length - 1) * 2; i >= length; i--)
        {
            int temp_i = temp[i];

            for (int j = 0; j < poly.length; j++)
            {
                temp[i - length + poly[j]] ^= temp_i;
            }
        }

        for (int i = 0; i < length; ++i)
        {
            out[i] = gf_reduce(temp[i]);
        }
    }

    protected void gf_sqr_poly(int length, int[] poly, short[] out, short[] input, int[] temp)
    {
        temp[0] = gf_sq_ext(input[0]);

        for (int i = 1; i < length; i++)
        {
            temp[i + i - 1] = 0;
            temp[i + i] = gf_sq_ext(input[i]);
        }

        for (int i = (length - 1) * 2; i >= length; i--)
        {
            int temp_i = temp[i];

            for (int j = 0; j < poly.length; j++)
            {
                temp[i - length + poly[j]] ^= temp_i;
            }
        }

        for (int i = 0; i < length; ++i)
        {
            out[i] = gf_reduce(temp[i]);
        }
    }

    /* input: field element den, num */
    /* return: (num/den) */
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

    protected short gf_inv(short den)
    {
        return gf_frac(den, (short)1);
    }

    protected short gf_mul(short in0, short in1)
    {
        int x = in0;
        int y = in1;

        int z = x * (y & 1);
        for (int i = 1; i < 13; i++)
        {
            z ^= x * (y & (1 << i));
        }

        return gf_reduce(z);
    }

    protected int gf_mul_ext(short in0, short in1)
    {
        int x = in0, y = in1;

        int z = x * (y & 1);
        for (int i = 1; i < 13; i++)
        {
            z ^= x * (y & (1 << i));
        }

        return z;
    }

    private int gf_mul_ext_par(short in0, short in1, short in2, short in3)
    {
        int x0 = in0, y0 = in1, x1 = in2, y1 = in3;
        
        int z0 = x0 * (y0 & 1);
        int z1 = x1 * (y1 & 1);

        for (int i = 1; i < 13; i++)
        {
            z0 ^= x0 * (y0 & (1 << i));
            z1 ^= x1 * (y1 & (1 << i));
        }

        return z0 ^ z1;
    }

    protected short gf_reduce(int x)
    {
//        assert (x >>> 26) == 0;

        int u0 = x & 0x00001FFF;
        int u1 = x >>> 13;

        int t2 = (u1 << 4) ^ (u1 << 3) ^ (u1 << 1);

        int u2 = t2 >>> 13;
        int u3 = t2 & 0x00001FFF;
        int u4 = (u2 << 4) ^ (u2 << 3) ^ (u2 << 1);

        return (short)(u0 ^ u1 ^ u2 ^ u3 ^ u4);
    }

    protected short gf_sq(short input)
    {
        int z = Interleave.expand16to32(input);
        return gf_reduce(z);
    }

    protected int gf_sq_ext(short input)
    {
        return Interleave.expand16to32(input);
    }

    /* input: field element in */
    /* return: (in^2)^2 */
    private short gf_sq2(short in)
    {
        int z1 = Interleave.expand16to32(in);
        in = gf_reduce(z1);
        int z2 = Interleave.expand16to32(in);
        return gf_reduce(z2);
    }

    /* input: field element in, m */
    /* return: (in^2)*m */
    private short gf_sqmul(short in, short m)
    {
        long t0 = in;
        long t1 = m;

        long x = (t1 << 6) * (t0 & (1 << 6));

        t0 ^= t0 << 7;

        x ^= (t1 << 0) * (t0 & 0x04001);
        x ^= (t1 << 1) * (t0 & 0x08002);
        x ^= (t1 << 2) * (t0 & 0x10004);
        x ^= (t1 << 3) * (t0 & 0x20008);
        x ^= (t1 << 4) * (t0 & 0x40010);
        x ^= (t1 << 5) * (t0 & 0x80020);

        long t;
        t  = x & 0x0000001FFC000000L;
        x ^= (t >>> 18) ^ (t >>> 20) ^ (t >>> 24) ^ (t >>> 26);

        return gf_reduce((int)x & 0x03FFFFFF);
    }

    /* input: field element in, m */
    /* return: ((in^2)^2)*m */
    private short gf_sq2mul(short in, short m)
    {
        long t0 = in;
        long t1 = m;

        long x = (t1 << 18) * (t0 & (1 << 6));

        t0 ^= t0 << 21;

        x ^= (t1 <<  0) * (t0 & (0x010000001L));
        x ^= (t1 <<  3) * (t0 & (0x020000002L));
        x ^= (t1 <<  6) * (t0 & (0x040000004L));
        x ^= (t1 <<  9) * (t0 & (0x080000008L));
        x ^= (t1 << 12) * (t0 & (0x100000010L));
        x ^= (t1 << 15) * (t0 & (0x200000020L));

        long t;
        t  = x & 0x1FFFF80000000000L;
        x ^= (t >>> 18) ^ (t >>> 20) ^ (t >>> 24) ^ (t >>> 26);

        t  = x & 0x000007FFFC000000L;
        x ^= (t >>> 18) ^ (t >>> 20) ^ (t >>> 24) ^ (t >>> 26);

        return gf_reduce((int)x & 0x03FFFFFF);
    }
}
