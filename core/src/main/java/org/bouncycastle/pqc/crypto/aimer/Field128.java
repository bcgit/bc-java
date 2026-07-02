package org.bouncycastle.pqc.crypto.aimer;

class Field128
    extends Field
{
    public Field128()
    {
        AIM2_NUM_WORDS_FIELD = 2;
        t = new long[AIM2_NUM_WORDS_FIELD];
        temp = new long[AIM2_NUM_WORDS_FIELD << 1];
    }

    public void GF_sqr_s(long[] c, long[] a)
    {
        long t;
        // Square the low 64 bits (a[0])
        poly64_sqr_s(temp, 0, a[0]);

        // Square the high 64 bits (a[1])
        poly64_sqr_s(temp, 2, a[1]);

        // The reduction step for the field
        t = temp[2] ^ ((temp[3] >>> 57) ^ (temp[3] >>> 62) ^ (temp[3] >>> 63));

        c[1] = reduce_high_word(temp[1], temp[3], t);
        c[0] = reduce_low_word(temp[0], t);
    }

    public void GF_mul_s(long[] c, long[] a, long[] b)
    {
        GF_mul(a, b);

        c[1] = reduce_high_word(temp[1], temp[3], t[0]);
        c[0] = reduce_low_word(temp[0], t[0]);
    }

    /**
     * GF multiplication with addition: c += a * b (schoolbook method)
     * This uses poly64_mul_s (schoolbook 64-bit multiplication)
     */
    public void GF_mul_add_s(long[] c, long[] a, long[] b)
    {
        GF_mul(a, b);
        c[1] ^= reduce_high_word(temp[1], temp[3], t[0]);
        c[0] ^= reduce_low_word(temp[0], t[0]);
    }

    private void GF_mul(long[] a, long[] b)
    {
        // Multiply high words: a[1] * b[1]
        poly64_mul_s(temp, 2, a[1], b[1]);
        // Multiply low words: a[0] * b[0]
        poly64_mul_s(temp, 0, a[0], b[0]);
        // Multiply (a[0] ^ a[1]) * (b[0] ^ b[1])
        poly64_mul_s(t, 0, a[0] ^ a[1], b[0] ^ b[1]);

        // Karatsuba combination
        temp[1] ^= t[0] ^ temp[0] ^ temp[2];
        temp[2] = t[0] ^ t[1] ^ temp[0] ^ temp[1] ^ temp[3];

        // Field reduction (for polynomial x^128 + x^7 + x^2 + x + 1)
        t[0] = temp[2] ^ ((temp[3] >>> 57) ^ (temp[3] >>> 62) ^ (temp[3] >>> 63));
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


        // table_b = in ^ (0xb6), table_5 = in ^ (0xb5)
        // Compute in^0xb0 = in^(11*16) using squarings
        GF_sqr_s(t1, table_b);  // in^11 -> in^22
        GF_sqr_s(t1, t1);       // in^22 -> in^44
        GF_sqr_s(t1, t1);       // in^44 -> in^88
        GF_sqr_s(t1, t1);       // in^88 -> in^176 (which is 0xb0 in decimal)
        // Now multiply by in^6 to get in^(0xb6)
        GF_mul_s(table_b, t1, table_6);  // in^0xb0 * in^6 = in^0xb6
        // And multiply by in^5 to get in^(0xb5)
        GF_mul_s(table_5, t1, table_5);  // in^0xb0 * in^5 = in^0xb5

        // t1 = in ^ (0xb6b6)
        GF_sqr_s(t1, table_b);  // in^0xb6 -> in^0x16c
        for (int i = 1; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_b);  // multiply by in^0xb6 to get in^(0xb6b6)

        // t1 = in ^ (0xb6b6 d)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_d);

        // t1 = in ^ (0xb6b6d 6)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_6);

        // t2 = in ^ (0xb6b6d6 d)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t2, t1, table_d);

        // t1 = in ^ (0xb6b6d6d 6)
        GF_sqr_s(t1, t2);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_6);

        // t1 = in ^ (0xb6b6d6d6 d)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_d);

        // t1 = in ^ (0xb6b6d6d6d a)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_a);

        // t1 = in ^ (0xb6b6d6d6da d)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_d);

        // t1 = in ^ (0xb6b6d6d6dad b5)
        for (int i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_5);

        // t1 = in ^ (0xb6b6d6d6dadb5 b5)
        for (int i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_5);

        // t1 = in ^ (0xb6b6d6d6dadb5b5 b6)
        for (int i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_b);

        // t1 = in ^ (0xb6b6d6d6dadb5b5b6 b6b6d6d)
        for (int i = 0; i < 28; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, t2);

        // t1 = in ^ (0xb6b6d6d6dadb5b5b6b6b6d6d a)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_a);

        // t1 = in ^ (0xb6b6d6d6dadb5b5b6b6b6d6da d)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_d);

        // t1 = in ^ (0xb6b6d6d6dadb5b5b6b6b6d6dad a)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_a);

        // t1 = in ^ (0xb6b6d6d6dadb5b5b6b6b6d6dada d)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_d);

        // t1 = in ^ (0xb6b6d6d6dadb5b5b6b6b6d6dadad b5)
        for (int i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_5);

        // t1 = in ^ (0xb6b6d6d6dadb5b5b6b6b6d6dadadb5 b5)
        for (int i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(out, t1, table_5);
    }

    /**
     * Inverse Mersenne S-box with e2 = 91
     */
    public void GF_exp_invmer_e_2(long[] out, long[] in)
    {
        long[] t1 = new long[AIM2_NUM_WORDS_FIELD];
        long[] t2 = new long[AIM2_NUM_WORDS_FIELD];
        long[] t3 = new long[AIM2_NUM_WORDS_FIELD];
        long[] table_5 = new long[AIM2_NUM_WORDS_FIELD];
        long[] table_6 = new long[AIM2_NUM_WORDS_FIELD];
        long[] table_a = new long[AIM2_NUM_WORDS_FIELD];
        long[] table_b = new long[AIM2_NUM_WORDS_FIELD];
        long[] table_d = new long[AIM2_NUM_WORDS_FIELD];

        // t1 = in ^ 4
        GF_sqr_s(table_d, in);
        GF_sqr_s(t1, table_d);

        // table_5 = in ^ 5
        GF_mul_s(table_5, t1, in);
        // table_6 = in ^ 6
        GF_mul_s(table_6, table_5, in);
        // table_a = in ^ 10 = (in ^ 5) ^ 2
        GF_sqr_s(table_a, table_5);
        // table_b = in ^ 11
        GF_mul_s(table_b, table_a, in);
        // table_d = in ^ 13
        GF_mul_s(table_d, table_b, table_d);

        // t3 = in ^ (0xb6), table_b = in ^ (0xb5)
        GF_sqr_s(t1, table_b);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(table_b, t1, table_5);  // in^0xb5
        GF_mul_s(t3, t1, table_6);       // in^0xb6

        // t2 = in ^ (0xb6 d)
        GF_sqr_s(t1, t3);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t2, t1, table_d);  // in^0xb6d

        // t1 = in ^ (0xb6d b5)
        GF_sqr_s(t1, t2);
        for (int i = 1; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_b);  // in^0xb6db5

        // t1 = in ^ (0xb6db5 b6d)
        for (int i = 0; i < 12; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, t2);  // in^0xb6db5b6d

        // t1 = in ^ (0xb6db5b6d a)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_a);  // in^0xb6db5b6da

        // t1 = in ^ (0xb6db5b6da d)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_d);  // in^0xb6db5b6dad

        // t1 = in ^ (0xb6db5b6dad b6d)
        for (int i = 0; i < 12; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, t2);  // in^0xb6db5b6dadb6d

        // t1 = in ^ (0xb6db5b6dadb6d a)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_a);

        // t1 = in ^ (0xb6db5b6dadb6da d)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_d);

        // t1 = in ^ (0xb6db5b6dadb6dad b6d)
        for (int i = 0; i < 12; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, t2);

        // t1 = in ^ (0xb6db5b6dadb6dadb6d 6)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_6);

        // t1 = in ^ (0xb6db5b6dadb6dadb6d6 d)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_d);

        // t1 = in ^ (0xb6db5b6dadb6dadb6d6d b6d)
        for (int i = 0; i < 12; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, t2);

        // t1 = in ^ (0xb6db5b6dadb6dadb6d6db6d 6)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_6);

        // t1 = in ^ (0xb6db5b6dadb6dadb6d6db6d6 d)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_d);

        // t1 = in ^ (0xb6db5b6dadb6dadb6d6db6d6d b6)
        for (int i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, t3);

        // t1 = in ^ (0xb6db5b6dadb6dadb6d6db6d6db6 b6d)
        for (int i = 0; i < 12; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, t2);

        // out = in ^ (0xb6db5b6dadb6dadb6d6db6d6db6b6d b5)
        for (int i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(out, t1, table_b);
    }

    /**
     * Mersenne exponentiation with e_star = 3
     * out = in^(2^3 - 1) = in^7
     */
    public void GF_exp_mer_e_star(long[] out, long[] in)
    {
        long[] t1 = new long[AIM2_NUM_WORDS_FIELD];
        GF_sqr_s(t1, in);
        GF_mul_s(t1, t1, in);
        GF_sqr_s(t1, t1);
        GF_mul_s(out, t1, in);
    }
}
