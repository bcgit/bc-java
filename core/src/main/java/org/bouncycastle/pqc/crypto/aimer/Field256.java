package org.bouncycastle.pqc.crypto.aimer;

class Field256
    extends Field
{
    private final long[] add;
    private final long[] mul;

    public Field256()
    {
        AIM2_NUM_WORDS_FIELD = 4;
        t = new long[AIM2_NUM_WORDS_FIELD];
        temp = new long[AIM2_NUM_WORDS_FIELD << 1];
        add = new long[AIM2_NUM_WORDS_FIELD];
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
        poly64_sqr_s(temp, 6, a[3]);

        t = temp[4] ^ ((temp[7] >>> 54) ^ (temp[7] >>> 59) ^ (temp[7] >>> 62));

        c[3] = reduce_high_word_256(temp[3], temp[7], temp[6]);
        c[2] = reduce_high_word_256(temp[2], temp[6], temp[5]);
        c[1] = reduce_high_word_256(temp[1], temp[5], t);
        c[0] = reduce_low_word_256(temp[0], t);
    }

    public void GF_mul_s(long[] c, long[] a, long[] b)
    {
        long red = GF_mul(a, b);

        c[3] = reduce_high_word_256(temp[3], temp[7], temp[6]);
        c[2] = reduce_high_word_256(temp[2], temp[6], temp[5]);
        c[1] = reduce_high_word_256(temp[1], temp[5], red);
        c[0] = reduce_low_word_256(temp[0], red);
    }

    /**
     * GF multiplication with addition: c += a * b (schoolbook method)
     * This uses poly64_mul_s (schoolbook 64-bit multiplication)
     */
    public void GF_mul_add_s(long[] c, long[] a, long[] b)
    {
        long red = GF_mul(a, b);

        c[3] ^= reduce_high_word_256(temp[3], temp[7], temp[6]);
        c[2] ^= reduce_high_word_256(temp[2], temp[6], temp[5]);
        c[1] ^= reduce_high_word_256(temp[1], temp[5], red);
        c[0] ^= reduce_low_word_256(temp[0], red);
    }

    private long GF_mul(long[] a, long[] b)
    {
        poly64_mul_s(mul, 0, a[0], b[0]);
        t[0] = mul[1];
        temp[0] = mul[0];
        poly64_mul_s(mul, 0, a[1], b[1]);
        t[2] = mul[1];
        t[1] = mul[0];
        t[0] ^= t[1];

        poly64_mul_s(mul, 0, a[2], b[2]);
        t[3] = mul[1];
        t[1] = mul[0];
        t[1] ^= t[2];

        poly64_mul_s(mul, 0, a[3], b[3]);
        temp[7] = mul[1];
        t[2] = mul[0];
        t[2] ^= t[3];

        temp[6] = temp[7] ^ t[2];
        temp[3] = t[2] ^ t[1];
        temp[2] = t[1] ^ t[0];
        temp[1] = t[0] ^ temp[0];

        poly64_mul_s_add(temp, 1, a[0] ^ a[1], b[0] ^ b[1]);

        poly64_mul_s(t, 0, a[2] ^ a[3], b[2] ^ b[3]);
        temp[3] ^= t[0];
        temp[6] ^= t[1];

        temp[5] = temp[7] ^ temp[3];
        temp[4] = temp[6] ^ temp[2];
        temp[3] ^= temp[1];
        temp[2] ^= temp[0];

        add[0] = a[0] ^ a[2];
        add[1] = a[1] ^ a[3];
        add[2] = b[0] ^ b[2];
        add[3] = b[1] ^ b[3];
        poly64_mul_s(t, 0, add[0], add[2]);
        poly64_mul_s(mul, 0, add[1], add[3]);
        t[3] = mul[1];
        t[2] = mul[0];
        t[1] ^= t[2];
        t[2] = t[1] ^ t[3];
        t[1] ^= t[0];

        temp[2] ^= t[0];
        temp[3] ^= t[1];
        temp[4] ^= t[2];
        temp[5] ^= t[3];

        poly64_mul_s_add(temp, 3, add[0] ^ add[1], add[2] ^ add[3]);

        return temp[4] ^ ((temp[7] >>> 54) ^ (temp[7] >>> 59) ^ (temp[7] >>> 62));
    }

    public void GF_exp_invmer_e_1(long[] out, long[] in)
    {
        int words = AIM2_NUM_WORDS_FIELD;
        long[] t1 = new long[words];
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
        GF_mul_s(table_b, table_5, table_6);

        // table_d = in ^ 13
        GF_mul_s(table_d, table_b, table_d);  // in^11 * in^2 = in^13

        // table_b = in ^ (0xb6), table_5 = in ^ (0xb5)
        GF_sqr_s(t1, table_b);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(table_5, t1, table_5);
        GF_mul_s(table_b, t1, table_6);

        // t1 = in ^ (0xb6 d)
        GF_sqr_s(t1, table_b);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_d);

        // t1 = in ^ (0xb6d 6)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_6);

        // t1 = in ^ (0xb6d6 d)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_d);

        // t1 = in ^ (0xb6d6d a)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_a);

        // t1 = in ^ (0xb6d6da d)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, table_d);

        // table_5 = in ^ (0xb6d6dad b5)
        for (int i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(table_5, t1, table_5);

        // t1 = in ^ (0xb6d6dadb5 b6)
        GF_sqr_s(t1, table_5);
        for (int i = 1; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_b);

        // t1 = in ^ (0xb6d6dadb5b6 b6d6dadb5)
        for (int i = 0; i < 36; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_5);

        // t1 = in ^ (0xb6d6dadb5b6b6d6dadb5 b6)
        for (int i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_b);

        // t1 = in ^ (0xb6d6dadb5b6b6d6dadb5b6 b6d6dadb5)
        for (int i = 0; i < 36; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_5);

        // t1 = in ^ (0xb6d6dadb5b6b6d6dadb5b6b6d6dadb5 b6)
        for (int i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_b);

        // t1 = in ^ (0xb6d6dadb5b6b6d6dadb5b6b6d6dadb5b6 b6d6dadb5)
        for (int i = 0; i < 36; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_5);

        // t1 = in ^ (0xb6d6dadb5b6b6d6dadb5b6b6d6dadb5b6b6d6dadb5 b6)
        for (int i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_b);

        // out = in ^ (0xb6d6dadb5b6b6d6dadb5b6b6d6dadb5b6b6d6dadb5b6 b6d6dadb5)
        for (int i = 0; i < 36; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_5);

        // t1 = in ^ (0xb6d6dadb5b6b6d6dadb5b6b6d6dadb5b6b6d6dadb5b6b6d6dadb5 b6)
        for (int i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_b);

        // out = in ^ (0xb6d6dadb5b6b6d6dadb5b6b6d6dadb5b6b6d6dadb5b6b6d6dadb5b6 b6d6dadb5)
        for (int i = 0; i < 36; i++)
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
        int words = AIM2_NUM_WORDS_FIELD;
        long[] t1 = new long[words];
        long[] t2 = new long[words];
        long[] t3 = new long[words];

        long[] t4 = new long[words];
        long[] t5 = new long[words];
        long[] table_9 = new long[words];
        // t2 = in ^ (0x11), table_9 = in ^ 9
        GF_sqr_s(t1, in);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(table_9, t1, in);
        GF_sqr_s(t1, t1);
        GF_mul_s(t2, t1, in);

        // t3 = in ^ (0x111)
        GF_sqr_s(t1, t2);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t3, t1, in);

        // t4 = in ^ (0x222444)
        GF_sqr_s(t1, t3);
        for (int i = 0; i < 10; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, t3);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t4, t1);

        // t1 = in ^ (0x222444 8889)
        GF_sqr_s(t1, t4);
        for (int i = 1; i < 9; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, t3);
        for (int i = 0; i < 7; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_9);

        // t1 = in ^ (0x2224448889 11)
        for (int i = 0; i < 8; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, t2);

        // t5 = in ^ (0x222444888911 2)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, in);
        GF_sqr_s(t5, t1);

        // t1 = in ^ (0x2224448889112 2224448889112)
        GF_sqr_s(t1, t5);
        for (int i = 1; i < 52; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, t5);

        // t1 = in ^ (0x22244488891122224448889112 222444)
        for (int i = 0; i < 24; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, t4);

        // t1 = in ^ (0x22244488891122224448889112222444 889)
        for (int i = 0; i < 5; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, t2);
        for (int i = 0; i < 7; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_9);

        // t1 = in ^ (0x22244488891122224448889112222444889 111)
        for (int i = 0; i < 12; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, t3);

        // t1 = in ^ (0x22244488891122224448889112222444889111 222444)
        for (int i = 0; i < 24; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, t4);

        // t1 = in ^ (0x22244488891122224448889112222444889111222444 4)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, in);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);

        // t1 = in ^ (0x222444888911222244488891122224448891112224444 889)
        for (int i = 0; i < 5; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, t2);
        for (int i = 0; i < 7; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_9);

        // t1 = in ^ (0x222444888911222244488891122224448891112224444889 111)
        for (int i = 0; i < 12; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, t3);

        // t1 = in ^ (0x222444888911222244488891122224448891112224444889111 222444)
        for (int i = 0; i < 24; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, t4);

        // t1 = in ^ (0x222444888911222244488891122224448891112224444889111222444 4)
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);
        GF_mul_s(t1, t1, in);
        GF_sqr_s(t1, t1);
        GF_sqr_s(t1, t1);

        // t1 = in ^ (0x2224448889112222444888911222244488911122244448891112224444 889)
        for (int i = 0; i < 5; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, t2);
        for (int i = 0; i < 7; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(t1, t1, table_9);

        // out = in ^ (0x2224448889112222444888911222244488911122244448891112224444889 111)
        for (int i = 0; i < 12; i++)
        {
            GF_sqr_s(t1, t1);
        }
        GF_mul_s(out, t1, t3);
    }

    /**
     * Mersenne exponentiation with e_star = 3
     * out = in^(2^3 - 1) = in^7
     */
    public void GF_exp_mer_e_star(long[] out, long[] in)
    {
        long[] t1 = new long[AIM2_NUM_WORDS_FIELD];
        GF_sqr_s(t1, in);
        // t1 = a ^ (2 ^ 2 - 1)
        GF_mul_s(t1, t1, in);

        // out = a ^ (2 ^ 3 - 1)
        GF_sqr_s(t1, t1);
        GF_mul_s(out, t1, in);
    }
}
