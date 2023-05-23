package org.bouncycastle.pqc.crypto.cmce;

import org.bouncycastle.math.raw.Interleave;

final class GF12
    extends GF
{
    GF12()
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

            for (int j = 0; j < poly.length - 1; j++)
            {
                temp[i - length + poly[j]] ^= temp_i;
            }
            {
                // NOTE: Safe because gf_reduce allows up to 24 bits, but gf_mul_ext(_par) only produces 23.
                temp[i - length] ^= temp_i << 1;
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

            for (int j = 0; j < poly.length -1; j++)
            {
                temp[i - length + poly[j]] ^= temp_i;
            }
            {
                // NOTE: Safe because gf_reduce allows up to 24 bits, but gf_sq_ext only produces 23.
                temp[i - length] ^= temp_i << 1;
            }
        }

        for (int i = 0; i < length; ++i)
        {
            out[i] = gf_reduce(temp[i]);
        }
    }

    protected short gf_frac(short den, short num)
    {
        return gf_mul(gf_inv(den), num);
    }

    protected short gf_inv(short input)
    {
        short tmp_11;
        short tmp_1111;

        short out = input;

        out = gf_sq(out);
        tmp_11 = gf_mul(out, input); // 11

        out = gf_sq(tmp_11);
        out = gf_sq(out);
        tmp_1111 = gf_mul(out, tmp_11); // 1111

        out = gf_sq(tmp_1111);
        out = gf_sq(out);
        out = gf_sq(out);
        out = gf_sq(out);
        out = gf_mul(out, tmp_1111); // 11111111

        out = gf_sq(out);
        out = gf_sq(out);
        out = gf_mul(out, tmp_11); // 1111111111

        out = gf_sq(out);
        out = gf_mul(out, input); // 11111111111

        return gf_sq(out); // 111111111110
    }

    protected short gf_mul(short left, short right)
    {
        int x = left;
        int y = right;

        int z = x * (y & 1);
        for (int i = 1; i < 12; i++)
        {
            z ^= x * (y & (1 << i));
        }

        return gf_reduce(z);
    }

    protected int gf_mul_ext(short left, short right)
    {
        int x = left, y = right;

        int z = x * (y & 1);
        for (int i = 1; i < 12; i++)
        {
            z ^= x * (y & (1 << i));
        }

        return z;
    }

    private int gf_mul_ext_par(short left0, short right0, short left1, short right1)
    {
        int x0 = left0, y0 = right0, x1 = left1, y1 = right1;

        int z0 = x0 * (y0 & 1);
        int z1 = x1 * (y1 & 1);

        for (int i = 1; i < 12; i++)
        {
            z0 ^= x0 * (y0 & (1 << i));
            z1 ^= x1 * (y1 & (1 << i));
        }

        return z0 ^ z1;
    }

    protected short gf_reduce(int x)
    {
//        assert (x >>> 24) == 0;

        int u0 = x & 0x00000FFF;
        int u1 = x >>> 12;
        int u2 = (x & 0x001FF000) >>> 9;
        int u3 = (x & 0x00E00000) >>> 18;
        int u4 = x >>> 21;

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
}
