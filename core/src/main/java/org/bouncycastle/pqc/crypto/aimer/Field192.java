package org.bouncycastle.pqc.crypto.aimer;

class Field192
    extends Field
{
    private final long[] mul;

    public Field192()
    {
        AIM2_NUM_WORDS_FIELD = 3;
        t = new long[AIM2_NUM_WORDS_FIELD];
        temp = new long[AIM2_NUM_WORDS_FIELD << 1];
        mul = new long[2];
    }


    public void GF_sqr_s(long[] c, long[] a)
    {
        long t;
        // Square the low 64 bits (a[0])
        poly64_sqr_s(temp, 0, a[0]);

        // Square the high 64 bits (a[1])
        poly64_sqr_s(temp, 2, a[1]);

        poly64_sqr_s(temp, 4, a[2]);
        t = temp[3] ^ ((temp[5] >>> 57) ^ (temp[5] >>> 62) ^ (temp[5] >>> 63));

        c[2] = reduce_high_word(temp[2], temp[5], temp[4]);
        c[1] = reduce_high_word(temp[1], temp[4], t);
        c[0] = reduce_low_word(temp[0], t);
    }

    public void GF_mul_s(long[] c, long[] a, long[] b)
    {
        long red = GF_mul(a, b);

        c[2] = reduce_high_word(temp[2], temp[5], temp[4]);
        c[1] = reduce_high_word(temp[1], temp[4], red);
        c[0] = reduce_low_word(temp[0], red);
    }

    /**
     * GF multiplication with addition: c += a * b (schoolbook method)
     * This uses poly64_mul_s (schoolbook 64-bit multiplication)
     */
    public void GF_mul_add_s(long[] c, long[] a, long[] b)
    {
        long red = GF_mul(a, b);

        c[2] ^= reduce_high_word(temp[2], temp[5], temp[4]);
        c[1] ^= reduce_high_word(temp[1], temp[4], red);
        c[0] ^= reduce_low_word(temp[0], red);
    }

    private long GF_mul(long[] a, long[] b)
    {
        poly64_mul_s(t, 0, a[1], b[1]);
        poly64_mul_s(mul, 0, a[0], b[0]);
        temp[0] = mul[0];
        t[0] ^= mul[1];


        poly64_mul_s(mul, 0, a[2], b[2]);
        temp[5] = mul[1];
        t[1] ^= mul[0];

        temp[1] = t[0] ^ temp[0];
        temp[2] = t[1] ^ temp[1];
        temp[4] = temp[5] ^ t[1];
        temp[3] = temp[4] ^ t[0];

        poly64_mul_s_add(temp, 1, a[0] ^ a[1], b[0] ^ b[1]);
        poly64_mul_s_add(temp, 2, a[0] ^ a[2], b[0] ^ b[2]);
        poly64_mul_s_add(temp, 3, a[1] ^ a[2], b[1] ^ b[2]);

        return temp[3] ^ ((temp[5] >>> 57) ^ (temp[5] >>> 62) ^ (temp[5] >>> 63));
    }

    public void GF_exp_invmer_e_1(long[] out, long[] in)
    {
        int words = AIM2_NUM_WORDS_FIELD;
        long[] t1 = new long[words];
        long[] t2 = new long[words];
        long[] table_5 = new long[words];
        long[] table_6 = new long[words];
        long[] table_a = new long[words];
        long[] table_b = new long[words];
        long[] table_d = new long[words];

        // t1 = in ^ 4
        GF_sqr_s(table_d, in);  // table_d = in^2
        GF_sqr_s(t1, table_d);  // t1 = (in^2)^2 = in^4

        // table_5 = in ^ 5
        GF_mul_s(table_5, t1, in);  // in^4 * in = in^5
        // table_6 = in ^ 6
        GF_mul_s(table_6, table_5, in);  // in^5 * in = in^6
        // table_a = in ^ 10 = (in ^ 5) ^ 2
        GF_sqr_s(table_a, table_5);  // (in^5)^2 = in^10

        // table_b = in ^ 11
        GF_mul_s(table_b, table_a, in);  // in^10 * in = in^11

        // table_d = in ^ 13
        GF_mul_s(table_d, table_b, table_d);  // in^11 * in^2 = in^13

        int i;
        // t1 = in ^ (0xad)
        GF_sqr_s(t1, table_a);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_d);

        // t2 = in ^ (0xad 6), table_d = in ^ (0xad5)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t2, t1, table_6);
        GF_mul_s(table_d, t1, table_5);

        // t1 = in ^ (0xad6 b)
        GF_sqr_s(t1, t2);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_b);

        // t1 = in ^ (0xad6b 5)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_5);

        // t1 = in ^ (0xad6b5 6)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_6);

        // t1 = in ^ (0xad6b56 b)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_b);

        // t1 = in ^ (0xad6b56b 5)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_5);

        // t1 = in ^ (0xad6b56b5 a)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_a);

        // t1 = in ^ (0xad6b56b5a b)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_b);

        // t1 = in ^ (0xad6b56b5ab 5)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_5);

        // table_d = in ^ (0xad6b56b5ab5 ad5)
        for (i = 0; i < 12; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(table_d, t1, table_d);

        // t1 = n ^ (0xad6b56b5ab5ad5 ad6)
        GF_sqr_s(t1, table_d);
        for (i = 1; i < 12; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, t2);

        // t1 = in ^ (0xad6b56b5ab5ad5ad6 ad6b56b5ab5ad5)
        for (i = 0; i < 56; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_d);

        // t1 = in ^ (0xad6b56b5ab5ad5ad6ad6b56b5ab5ad5 ad6)
        for (i = 0; i < 12; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, t2);

        // t1 = in ^ (0xad6b56b5ab5ad5ad6ad6b56b5ab5ad5ad6 ad6b56b5ab5ad5)
        for (i = 0; i < 56; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(out, t1, table_d);
    }

    /**
     * Inverse Mersenne S-box with e2 = 91
     */
    public void GF_exp_invmer_e_2(long[] out, long[] in)
    {
        int words = AIM2_NUM_WORDS_FIELD;
        long[] t1 = new long[words];
        long[] t2 = new long[words];
        long[] table_6 = new long[words];
        long[] table_b = new long[words];
        long[] table_d = new long[words];

        // t1 = in ^ 4
        GF_sqr_s(table_d, in);
        GF_sqr_s(t1, table_d);


        long[] table_7 = new long[words];
        long[] table_e = new long[words];
        int i;
        // t1 = in ^ 3
        GF_sqr_s(table_d, in);
        GF_mul_s(t1, table_d, in);

        // table_6 = (in ^ 3) ^ 2
        GF_sqr_s(table_6, t1);
        // table_7 = in ^ 7
        GF_mul_s(table_7, table_6, in);
        // table_b = in ^ 11
        GF_sqr_s(table_b, table_d);
        GF_mul_s(table_b, table_b, table_7);
        // table_d = in ^ 13
        GF_mul_s(table_d, table_6, table_7);
        // table_e = in ^ 14
        GF_sqr_s(table_e, table_7);

        // table_b = in ^ (0xbb)
        GF_sqr_s(t1, table_b);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(table_b, t1, table_b);

        // table_7 = in ^ (0x77), table_6 = in ^ (0x76)
        GF_sqr_s(t1, table_7);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(table_6, t1, table_6);
        GF_mul_s(table_7, t1, table_7);

        // t2 = in ^ (0xdd)
        GF_sqr_s(t1, table_d);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t2, t1, table_d);

        // table_e = in ^ (0xee), table_d = in ^ (0xed)
        GF_sqr_s(t1, table_e);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(table_d, t1, table_d);
        GF_mul_s(table_e, t1, table_e);

        // t2 = in ^ (0xdd dd)
        GF_sqr_s(t1, t2);
        for (i = 1; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t2, t1, t2);

        // t1 = in ^ (0xdddd dddd)
        GF_sqr_s(t1, t2);
        for (i = 1; i < 16; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, t2);

        // t1 = in ^ (0xdddddddd dddd)
        for (i = 0; i < 16; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, t2);

        // t1 = in ^ (0xdddddddddddd bb)
        for (i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_b);

        // t1 = in ^ (0xddddddddddddbb bb)
        for (i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_b);

        // t1 = in ^ (0xddddddddddddbbbb bb)
        for (i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_b);

        // t1 = in ^ (0xddddddddddddbbbbbb bb)
        for (i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_b);

        // t1 = in ^ (0xddddddddddddbbbbbbbb bb)
        for (i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_b);

        // t1 = in ^ (0xddddddddddddbbbbbbbbbb bb)
        for (i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_b);

        // t1 = in ^ (0xddddddddddddbbbbbbbbbbbb 77)
        for (i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_7);

        // t1 = in ^ (0xddddddddddddbbbbbbbbbbbb77 77)
        for (i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_7);

        // t1 = in ^ (0xddddddddddddbbbbbbbbbbbb7777 77)
        for (i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_7);

        // t1 = in ^ (0xddddddddddddbbbbbbbbbbbb777777 77)
        for (i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_7);

        // t1 = in ^ (0xddddddddddddbbbbbbbbbbbb77777777 77)
        for (i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_7);

        // t1 = in ^ (0xddddddddddddbbbbbbbbbbbb7777777777 76)
        for (i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_6);

        // t1 = in ^ (0xddddddddddddbbbbbbbbbbbb777777777776 ee)
        for (i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_e);

        // t1 = in ^ (0xddddddddddddbbbbbbbbbbbb777777777776ee ee)
        for (i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_e);

        // t1 = in ^ (0xddddddddddddbbbbbbbbbbbb777777777776eeee ee)
        for (i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_e);

        // t1 = in ^ (0xddddddddddddbbbbbbbbbbbb777777777776eeeeee ee)
        for (i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_e);

        // t1 = in ^ (0xddddddddddddbbbbbbbbbbbb777777777776eeeeeeee ee)
        for (i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_e);

        // out = in ^ (0xddddddddddddbbbbbbbbbbbb777777777776eeeeeeeeee ed)
        for (i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(out, t1, table_d);
    }

    /**
     * Mersenne exponentiation with e_star = 3
     * out = in^(2^3 - 1) = in^7
     */
    public void GF_exp_mer_e_star(long[] out, long[] in)
    {
        long[] t1 = new long[AIM2_NUM_WORDS_FIELD];
        long[] t2 = new long[AIM2_NUM_WORDS_FIELD];
        GF_sqr_s(t1, in);
        // t2 = a ^ (2 ^ 2 - 1)
        GF_mul_s(t2, t1, in);

        // t1 = a ^ (2 ^ 3 - 1)
        GF_sqr_s(t1, t2);
        GF_mul_s(t1, t1, in);

        // out = a ^ (2 ^ 5 - 1)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(out, t1, t2);
    }
}
