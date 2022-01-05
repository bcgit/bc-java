package org.bouncycastle.pqc.crypto.cmce;

class GF12
    extends GF
{


    public GF12(int gfbits)
    {
        super(gfbits);
    }

    @Override
    protected short gf_mul(short left, short right)
    {
        int temp, temp_left, temp_right, t;
        temp_left = left;
        temp_right = right;
        temp = temp_left * (temp_right & 1);

        for (int i = 1; i < GFBITS; i++)
        {
            temp ^= (temp_left * (temp_right & (1<<i)));
        }

        t = (temp & 0x7FC000);
        temp ^= t >> 9;
        temp ^= t >> 12;

        t = (temp & 0x3000);
        temp ^= t >> 9;
        temp ^= t >> 12;

        short res = (short) ( temp & ((1 << GFBITS)-1));
        return res;

    }

    protected short gf_sq(short input)
    {
        int[] B = {0x55555555, 0x33333333, 0x0F0F0F0F, 0x00FF00FF};
        int x = input;
        int t;

        x = (x | (x << 8)) & B[3];
        x = (x | (x << 4)) & B[2];
        x = (x | (x << 2)) & B[1];
        x = (x | (x << 1)) & B[0];

        t = x & 0x7FC000;

        x ^= t >> 9;
        x ^= t >> 12;

        t = x & 0x3000;

        x ^= t >> 9;
        x ^= t >> 12;

        return (short) (x & ((1 << GFBITS)-1));
    }

    @Override
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

    @Override
    protected short gf_frac(short den, short num)
    {
        return gf_mul(gf_inv(den), num);
    }

}
