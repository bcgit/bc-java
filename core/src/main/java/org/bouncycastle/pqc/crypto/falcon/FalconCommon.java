package org.bouncycastle.pqc.crypto.falcon;

class FalconCommon
{
    FalconCommon()
    {
    }

    /* see inner.h */
    void hash_to_point_vartime(SHAKE256 sc, short[] srcx, int x, int logn)
    {
        /*
         * This is the straightforward per-the-spec implementation. It
         * is not constant-time, thus it might reveal information on the
         * plaintext (at least, enough to check the plaintext against a
         * list of potential plaintexts) in a scenario where the
         * attacker does not have access to the signature value or to
         * the public key, but knows the nonce (without knowledge of the
         * nonce, the hashed output cannot be matched against potential
         * plaintexts).
         */
        int n;

        n = 1 << logn;
        while (n > 0)
        {
            byte[] buf = new byte[2];
            int w; // unsigned

//            inner_shake256_extract(sc, (void *)buf, sizeof buf);
            sc.inner_shake256_extract(buf, 0, 2);
            w = ((buf[0] & 0xff) << 8) | (buf[1] & 0xff);
            if (w < 61445)
            {
                while (w >= 12289)
                {
                    w -= 12289;
                }
                srcx[x++] = (short)w;
                n--;
            }
        }
    }

    void hash_to_point_ct(
        SHAKE256 sc,
        short[] srcx, int x, int logn, short[] srctmp, int tmp)
    {
        /*
         * Each 16-bit sample is a value in 0..65535. The value is
         * kept if it falls in 0..61444 (because 61445 = 5*12289)
         * and rejected otherwise; thus, each sample has probability
         * about 0.93758 of being selected.
         *
         * We want to oversample enough to be sure that we will
         * have enough values with probability at least 1 - 2^(-256).
         * Depending on degree N, this leads to the following
         * required oversampling:
         *
         *   logn     n  oversampling
         *     1      2     65
         *     2      4     67
         *     3      8     71
         *     4     16     77
         *     5     32     86
         *     6     64    100
         *     7    128    122
         *     8    256    154
         *     9    512    205
         *    10   1024    287
         *
         * If logn >= 7, then the provided temporary buffer is large
         * enough. Otherwise, we use a stack buffer of 63 entries
         * (i.e. 126 bytes) for the values that do not fit in tmp[].
         */

        short overtab[] = {
            0, /* unused */
            65,
            67,
            71,
            77,
            86,
            100,
            122,
            154,
            205,
            287
        };

        int n, n2, u, m, p, over;
        int tt1;
        short[] tt2 = new short[63];

        /*
         * We first generate m 16-bit value. Values 0..n-1 go to x[].
         * Values n..2*n-1 go to tt1[]. Values 2*n and later go to tt2[].
         * We also reduce modulo q the values; rejected values are set
         * to 0xFFFF.
         */
        n = 1 << logn;
        n2 = n << 1;
        over = overtab[logn];
        m = n + over;
        tt1 = tmp;
        for (u = 0; u < m; u++)
        {
            byte[] buf = new byte[2];
            int w, wr;

            sc.inner_shake256_extract(buf, 0, buf.length);
            w = ((buf[0] & 0xff) << 8) | (buf[1] & 0xff);
            wr = w - (24578 & (((w - 24578) >>> 31) - 1));
            wr = wr - (24578 & (((wr - 24578) >>> 31) - 1));
            wr = wr - (12289 & (((wr - 12289) >>> 31) - 1));
            wr |= ((w - 61445) >>> 31) - 1;
            if (u < n)
            {
                srcx[x + u] = (short)wr;
            }
            else if (u < n2)
            {
                srctmp[tt1 + u - n] = (short)wr;
            }
            else
            {
                tt2[u - n2] = (short)wr;
            }
        }

        /*
         * Now we must "squeeze out" the invalid values. We do this in
         * a logarithmic sequence of passes; each pass computes where a
         * value should go, and moves it down by 'p' slots if necessary,
         * where 'p' uses an increasing powers-of-two scale. It can be
         * shown that in all cases where the loop decides that a value
         * has to be moved down by p slots, the destination slot is
         * "free" (i.e. contains an invalid value).
         */
        for (p = 1; p <= over; p <<= 1)
        {
            int v;

            /*
             * In the loop below:
             *
             *   - v contains the index of the final destination of
             *     the value; it is recomputed dynamically based on
             *     whether values are valid or not.
             *
             *   - u is the index of the value we consider ("source");
             *     its address is s.
             *
             *   - The loop may swap the value with the one at index
             *     u-p. The address of the swap destination is d.
             */
            v = 0;
            for (u = 0; u < m; u++)
            {
                int s, d;
                int sp, dp;
                int j, sv, dv, mk;

                if (u < n)
                {
                    sp = 1;
                    s = x + u;
                    sv = srcx[s];
                }
                else if (u < n2)
                {
                    sp = 2;
                    s = tt1 + u - n;
                    sv = srctmp[s];
                }
                else
                {
                    sp = 3;
                    s = u - n2;
                    sv = tt2[s];
                }

                /*
                 * The value in sv should ultimately go to
                 * address v, i.e. jump back by u-v slots.
                 */
                j = u - v;

                /*
                 * We increment v for the next iteration, but
                 * only if the source value is valid. The mask
                 * 'mk' is -1 if the value is valid, 0 otherwise,
                 * so we _subtract_ mk.
                 */
                mk = (sv >>> 15) - 1;
                v -= mk;

                /*
                 * In this loop we consider jumps by p slots; if
                 * u < p then there is nothing more to do.
                 */
                if (u < p)
                {
                    continue;
                }

                /*
                 * Destination for the swap: value at address u-p.
                 */
                if ((u - p) < n)
                {
                    dp = 1;
                    d = x + u - p;
                    dv = srcx[d];
                }
                else if ((u - p) < n2)
                {
                    dp = 2;
                    d = tt1 + (u - p) - n;
                    dv = srctmp[d];
                }
                else
                {
                    dp = 3;
                    d = (u - p) - n2;
                    dv = tt2[d];
                }

                /*
                 * The swap should be performed only if the source
                 * is valid AND the jump j has its 'p' bit set.
                 */
                mk &= -(((j & p) + 0x1FF) >> 9);
                if (sp == 1)
                {
                    srcx[s] = (short)(sv ^ (mk & (sv ^ dv)));
                }
                else if (sp == 2)
                {
                    srctmp[s] = (short)(sv ^ (mk & (sv ^ dv)));
                }
                else
                {
                    tt2[s] = (short)(sv ^ (mk & (sv ^ dv)));
                }
                if (dp == 1)
                {
                    srcx[d] = (short)(dv ^ (mk & (sv ^ dv)));
                }
                else if (dp == 2)
                {
                    srctmp[d] = (short)(dv ^ (mk & (sv ^ dv)));
                }
                else
                {
                    tt2[d] = (short)(dv ^ (mk & (sv ^ dv)));
                }
            }
        }
    }

    /*
     * Acceptance bound for the (squared) l2-norm of the signature depends
     * on the degree. This array is indexed by logn (1 to 10). These bounds
     * are _inclusive_ (they are equal to floor(beta^2)).
     */
    static final int l2bound[] = {
        0,    /* unused */
        101498,
        208714,
        428865,
        892039,
        1852696,
        3842630,
        7959734,
        16468416,
        34034726,
        70265242
    };

    /* see inner.h */
    int is_short(
        short[] srcs1, int s1, short[] srcs2, int s2, int logn)
    {
        /*
         * We use the l2-norm. Code below uses only 32-bit operations to
         * compute the square of the norm with saturation to 2^32-1 if
         * the value exceeds 2^31-1.
         */
        int n, u;
        int s, ng;

        n = 1 << logn;
        s = 0;
        ng = 0;
        for (u = 0; u < n; u++)
        {
            int z;

            z = srcs1[s1 + u];
            s += (z * z);
            ng |= s;
            z = srcs2[s2 + u];
            s += (z * z);
            ng |= s;
        }
        s |= -(ng >>> 31);

        return (s & 0xffffffffL) <= l2bound[logn] ? 1 : 0;
    }

    /* see inner.h */
    int is_short_half(
        int sqn, short[] srcs2, int s2, int logn)
    {
        int n, u;
        int ng;

        n = 1 << logn;
        ng = -(sqn >>> 31);
        for (u = 0; u < n; u++)
        {
            int z;

            z = srcs2[s2 + u];
            sqn += (z * z);
            ng |= sqn;
        }
        sqn |= -(ng >>> 31);

        return ((sqn & 0xffffffffL) <= l2bound[logn]) ? 1 : 0;
    }
}
