package org.bouncycastle.pqc.crypto.falcon;


/**
 * custom big integer implementation from the reference code
 */
class FalconBigInt
{
    int[] num;

    /**
     * construct a big int with n words available
     */
    FalconBigInt(int n)
    {
        this.num = new int[n];
        for (int i = 0; i < n; i++)
        {
            this.num[i] = 0;
        }
    }

    /**
     * wraps an array of ints as a big int
     */
    FalconBigInt(int[] nums)
    {
        this.num = nums;
    }

    static int[][] to_array2d(FalconBigInt[] xx, int num)
    {
        int[][] res = new int[num][];
        for (int i = 0; i < xx.length; i++)
        {
            res[i] = xx[i].num;
        }
        return res;
    }

    /**
     * subtracts b from this
     * carry is returned
     */
    int sub(FalconBigInt b, int len, int ctl)
    {
        int u;
        int cc, m;
        cc = 0;
        m = -ctl;
        for (u = 0; u < len; u++)
        {
            int aw, w;
            aw = this.num[u];
            w = aw - b.num[u] - cc;
            cc = w >>> 31;
            aw ^= ((w & 0x7FFFFFFF) ^ aw) & m;
            this.num[u] = aw;
        }
        return cc;
    }

    /**
     * multiplies by a small number
     * carry is returned
     */
    int mul_small(int len, int x)
    {
        int u, cc;
        cc = 0;
        for (u = 0; u < len; u++)
        {
            long z;
            z = FalconCommon.uint_long(this.num[u]) * FalconCommon.uint_long(x) + cc;
            this.num[u] = (int)z & 0x7FFFFFFF;
            cc = (int)(z >>> 31);
        }
        return cc;
    }

    /**
     * reduces a big integer modulo a small integer where:
     * this is unsigned
     * p is prime
     * 2^30 < p < 2^31
     * p0i = -(1/p) mod 2^31
     * R2 = 2^62 mod p
     */
    int mod_small_unsigned(int len, int p, int p0i, int R2)
    {
        int x, u;
        x = 0;
        u = len;
        while (u-- > 0)
        {
            int w;
            x = FalconCommon.modp_montymul(x, R2, p, p0i);
            w = this.num[u] - p;
            w += p & -(w >>> 31);
            x = FalconCommon.modp_add(x, w, p);
        }
        return x;
    }

    /**
     * Similar to mod_small_unsigned except for this being signed
     * Rx = 2^(31*this.num.length) mod p
     */
    int mod_small_signed(int len, int p, int p0i, int R2, int Rx)
    {
        int z;
        if (len == 0)
        {
            return 0;
        }
        z = this.mod_small_unsigned(len, p, p0i, R2);
        z = FalconCommon.modp_sub(z, Rx & -(this.num[len - 1] >>> 30), p);
        return z;
    }

    /**
     * add y*s to this
     */
    void add_mul_small(FalconBigInt y, int len, int s)
    {
        int u, cc;
        cc = 0;
        for (u = 0; u < len; u++)
        {
            int xw, yw;
            long z;
            xw = this.num[u];
            yw = y.num[u];
            z = FalconCommon.uint_long(yw) * FalconCommon.uint_long(s) + FalconCommon.uint_long(xw) + FalconCommon.uint_long(cc);
            this.num[u] = (int)z & 0x7FFFFFFF;
            cc = (int)(z >>> 31);
        }
        this.num[len] = cc;
    }

    /**
     * normalize a modular integer around 0:
     * if this > p/2 then this is replaced with this - p, otherwise it is untouched
     */
    void norm_zero(FalconBigInt p, int len)
    {
        int u;
        int r, bb;
        // compare x with p/2
        r = 0;
        bb = 0;
        u = len;
        while (u-- > 0)
        {
            int wx, wp, cc;
            // get two words to compare in wx, wp
            wx = this.num[u];
            wp = (p.num[u] >>> 1) | (bb << 30);
            bb = p.num[u] & 1;
            // cc set to -1, 0, or 1 based on wp < wx
            cc = wp - wx;
            cc = ((-cc) >>> 31) | -(cc >>> 31);
            // if r != 0 then it is either -1 or 1. If r == 0, replace with cc
            r |= cc & ((r & 1) - 1);
        }
        this.sub(p, len, r >>> 31); // subtract only if r == -1
    }

    /**
     * rebuild integer from RNS notation
     * xx is the array of residues
     * xlen = size of num in each xx index
     * xstride = step to access next int in xx (= 1 since we have array indexes instead of pointers)
     * num = length of xx
     */
    static FalconBigInt rebuild_CRT(FalconBigInt[] xx, int xlen, FalconSmallPrime[] primes,
                                    int normalise_signed, int[] tmp)
    {
        int u;
        int num = xx.length;
        FalconBigInt x;
        FalconBigInt t = new FalconBigInt(tmp);
        t.num[0] = primes[0].p;
        for (u = 1; u < xlen; u++)
        {
            int p, p0i, s, R2;
            int v;
            p = primes[u].p;
            s = primes[u].s;
            p0i = FalconCommon.modp_ninv31(p);
            R2 = FalconCommon.modp_R2(p, p0i);

            for (v = 0, x = xx[v]; v < num; v++)
            {
                int xp, xq, xr;
                /*
                 * xp = the integer x modulo the prime p for this
                 *      iteration
                 * xq = (x mod q) mod p
                 */
                xp = x.num[u];
                xq = x.mod_small_unsigned(u, p, p0i, R2);
                /*
                 * New value is (x mod q) + q * (s * (xp - xq) mod p)
                 */
                xr = FalconCommon.modp_montymul(s, FalconCommon.modp_sub(xp, xq, p), p, p0i);
                x.add_mul_small(t, u, xr);
            }
            t.num[u] = t.mul_small(u, p);
        }
        // normalise result around 0
        if (normalise_signed != 0)
        {
            for (u = 0, x = xx[u]; u < num; u++)
            {
                x.norm_zero(t, xlen);
            }
        }
        return new FalconBigInt(FalconCommon.array_flatten(to_array2d(xx, num), xlen, num));
    }

    /**
     * negates a big int
     */
    void negate(int len, int ctl)
    {
        int u;
        int cc, m;
        cc = ctl;
        m = -ctl >>> 1;
        for (u = 0; u < len; u++)
        {
            int aw;
            aw = this.num[u];
            aw = (aw ^ m) + cc;
            this.num[u] = aw & 0x7FFFFFFF;
            cc = aw >>> 31;
        }
    }

    /*
     * Replace a with (a*xa+b*xb)/(2^31) and b with (a*ya+b*yb)/(2^31).
     * The low bits are dropped (the caller should compute the coefficients
     * such that these dropped bits are all zeros). If either or both
     * yields a negative value, then the value is negated.
     *
     * Returned value is:
     *  0  both values were positive
     *  1  new a had to be negated
     *  2  new b had to be negated
     *  3  both new a and new b had to be negated
     *
     * Coefficients xa, xb, ya and yb may use the full signed 32-bit range.
     */
    static int co_reduce(FalconBigInt a, FalconBigInt b, int len,
                         long xa, long xb, long ya, long yb)
    {
        int u;
        long cca, ccb;
        int nega, negb;
        cca = 0;
        ccb = 0;
        for (u = 0; u < len; u++)
        {
            int wa, wb;
            long za, zb;
            wa = a.num[u];
            wb = b.num[u];
            za = wa * xa + wb * xb + cca;
            zb = wa * ya + wb * yb + ccb;
            if (u > 0)
            {
                a.num[u - 1] = (int)za & 0x7FFFFFFF;
                b.num[u - 1] = (int)zb & 0x7FFFFFFF;
            }
            cca = za >> 31;
            ccb = zb >> 31;
        }
        a.num[len - 1] = (int)cca;
        b.num[len - 1] = (int)ccb;

        nega = (int)(cca >>> 63);
        negb = (int)(ccb >>> 63);
        a.negate(len, nega);
        b.negate(len, negb);
        return nega | (negb << 1);
    }

    /*
     * Finish modular reduction. Rules on input parameters:
     *
     *   if neg = 1, then -m <= a < 0
     *   if neg = 0, then 0 <= a < 2*m
     *
     * If neg = 0, then the top word of a[] is allowed to use 32 bits.
     *
     * Modulus m must be odd.
     */
    void finish_mod(int len, FalconBigInt m, int neg)
    {
        int u;
        int cc, xm, ym;
        cc = 0;
        for (u = 0; u < len; u++)
        {
            cc = (this.num[u] - m.num[u] - cc) >>> 31;
        }
        xm = -neg >>> 1;
        ym = -(neg | (1 - cc));
        cc = neg;
        for (u = 0; u < len; u++)
        {
            int aw, mw;
            aw = this.num[u];
            mw = (m.num[u] ^ xm) & ym;
            aw = aw - mw - cc;
            this.num[u] = aw & 0x7FFFFFFF;
            cc = aw >>> 31;
        }
    }

    /*
     * Replace a with (a*xa+b*xb)/(2^31) mod m, and b with
     * (a*ya+b*yb)/(2^31) mod m. Modulus m must be odd; m0i = -1/m[0] mod 2^31.
     */
    static void co_reduce_mod(FalconBigInt a, FalconBigInt b, FalconBigInt m, int len,
                              int m0i, long xa, long xb, long ya, long yb)
    {
        int u;
        long cca, ccb;
        int fa, fb;
        cca = 0;
        ccb = 0;
        fa = ((a.num[0] * (int)xa + b.num[0] * (int)xb) * m0i) & 0x7FFFFFFF;
        fb = ((a.num[0] * (int)ya + b.num[0] * (int)yb) * m0i) & 0x7FFFFFFF;
        for (u = 0; u < len; u++)
        {
            int wa, wb;
            long za, zb;
            wa = a.num[u];
            wb = b.num[u];
            za = wa * xa + wb * xb + m.num[u] * FalconCommon.uint_long(fa) + cca;
            zb = wa * ya + wb * yb + m.num[u] * FalconCommon.uint_long(fb) + ccb;
            if (u > 0)
            {
                a.num[u - 1] = (int)za & 0x7FFFFFFF;
                b.num[u - 1] = (int)zb & 0x7FFFFFFF;
            }
            cca = za >> 31;
            ccb = zb >> 31;
        }
        a.num[len - 1] = (int)cca;
        b.num[len - 1] = (int)ccb;
        a.finish_mod(len, m, (int)(cca >>> 63));
        b.finish_mod(len, m, (int)(ccb >>> 63));
    }

    /*
     * Compute a GCD between two positive big integers x and y. The two
     * integers must be odd. Returned value is 1 if the GCD is 1, 0
     * otherwise. When 1 is returned, arrays u and v are filled with values
     * such that:
     *   0 <= u <= y
     *   0 <= v <= x
     *   x*u - y*v = 1
     * x[] and y[] are unmodified. Both input values must have the same
     * encoded length. Temporary array must be large enough to accommodate 4
     * extra values of that length. Arrays u, v and tmp may not overlap with
     * each other, or with either x or y.
     */
    static FalconGcdRes bezout(FalconBigInt x, FalconBigInt y, int len)
    {
        FalconBigInt u0, u1, v0, v1, a, b;
        int x0i, y0i;
        int num, rc;
        int j;
        if (len == 0)
        {
            return new FalconGcdRes();
        }
        u0 = new FalconBigInt(len);
        v0 = new FalconBigInt(len);
        x0i = FalconCommon.modp_ninv31(x.num[0]);
        y0i = FalconCommon.modp_ninv31(y.num[0]);
        /*
         * Initialize a, b, u0, u1, v0 and v1.
         *  a = x   u0 = 1   v0 = 0
         *  b = y   u1 = y   v1 = x-1
         * Note that x is odd, so computing x-1 is easy.
         */
        a = new FalconBigInt(x.num.clone());
        b = new FalconBigInt(y.num.clone());
        u0.num[0] = 1;
        u1 = new FalconBigInt(y.num.clone());
        v1 = new FalconBigInt(x.num.clone());
        v1.num[0]--;
        /*
         * Each input operand may be as large as 31*len bits, and we
         * reduce the total length by at least 30 bits at each iteration.
         */
        for (num = 62 * len + 30; num >= 30; num -= 30)
        {
            int c0, c1;
            int a0, a1, b0, b1;
            long a_hi, b_hi;
            int a_lo, b_lo;
            long pa, pb, qa, qb;
            int i;
            int r;
            /*
             * Extract the top words of a and b. If j is the highest
             * index >= 1 such that a[j] != 0 or b[j] != 0, then we
             * want (a[j] << 31) + a[j-1] and (b[j] << 31) + b[j-1].
             * If a and b are down to one word each, then we use
             * a[0] and b[0].
             */
            c0 = -1;
            c1 = -1;
            a0 = 0;
            a1 = 0;
            b0 = 0;
            b1 = 0;
            j = len;
            while (j-- > 0)
            {
                int aw, bw;

                aw = a.num[j];
                bw = b.num[j];
                a0 ^= (a0 ^ aw) & c0;
                a1 ^= (a1 ^ aw) & c1;
                b0 ^= (b0 ^ bw) & c0;
                b1 ^= (b1 ^ bw) & c1;
                c1 = c0;
                c0 &= (((aw | bw) + 0x7FFFFFFF) >>> 31) - 1;
            }
            /*
             * If c1 = 0, then we grabbed two words for a and b.
             * If c1 != 0 but c0 = 0, then we grabbed one word. It
             * is not possible that c1 != 0 and c0 != 0, because that
             * would mean that both integers are zero.
             */
            a1 |= a0 & c1;
            a0 &= ~c1;
            b1 |= b0 & c1;
            b0 &= ~c1;
            a_hi = (FalconCommon.uint_long(a0) << 31) + a1;
            b_hi = (FalconCommon.uint_long(b0) << 31) + b1;
            a_lo = a.num[0];
            b_lo = b.num[0];
            /*
             * Compute reduction factors:
             *
             *   a' = a*pa + b*pb
             *   b' = a*qa + b*qb
             *
             * such that a' and b' are both multiple of 2^31, but are
             * only marginally larger than a and b.
             */
            pa = 1;
            pb = 0;
            qa = 0;
            qb = 1;
            for (i = 0; i < 31; i++)
            {
                /*
                 * At each iteration:
                 *
                 *   a <- (a-b)/2 if: a is odd, b is odd, a_hi > b_hi
                 *   b <- (b-a)/2 if: a is odd, b is odd, a_hi <= b_hi
                 *   a <- a/2 if: a is even
                 *   b <- b/2 if: a is odd, b is even
                 *
                 * We multiply a_lo and b_lo by 2 at each
                 * iteration, thus a division by 2 really is a
                 * non-multiplication by 2.
                 */
                int rt, oa, ob, cAB, cBA, cA;
                long rz;

                /*
                 * rt = 1 if a_hi > b_hi, 0 otherwise.
                 */
                rz = b_hi - a_hi;
                rt = (int)((rz ^ ((a_hi ^ b_hi)
                    & (a_hi ^ rz))) >>> 63);

                /*
                 * cAB = 1 if b must be subtracted from a
                 * cBA = 1 if a must be subtracted from b
                 * cA = 1 if a must be divided by 2
                 *
                 * Rules:
                 *
                 *   cAB and cBA cannot both be 1.
                 *   If a is not divided by 2, b is.
                 */
                oa = (a_lo >> i) & 1;
                ob = (b_lo >> i) & 1;
                cAB = oa & ob & rt;
                cBA = oa & ob & ~rt;
                cA = cAB | (oa ^ 1);

                /*
                 * Conditional subtractions.
                 */
                a_lo -= b_lo & -cAB;
                a_hi -= b_hi & -FalconCommon.uint_long(cAB);
                pa -= qa & -(long)cAB;
                pb -= qb & -(long)cAB;
                b_lo -= a_lo & -cBA;
                b_hi -= a_hi & -FalconCommon.uint_long(cBA);
                qa -= pa & -(long)cBA;
                qb -= pb & -(long)cBA;

                /*
                 * Shifting.
                 */
                a_lo += a_lo & (cA - 1);
                pa += pa & ((long)cA - 1);
                pb += pb & ((long)cA - 1);
                a_hi ^= (a_hi ^ (a_hi >> 1)) & -FalconCommon.uint_long(cA);
                b_lo += b_lo & -cA;
                qa += qa & -(long)cA;
                qb += qb & -(long)cA;
                b_hi ^= (b_hi ^ (b_hi >> 1)) & (FalconCommon.uint_long(cA) - 1);
            }
            r = FalconBigInt.co_reduce(a, b, len, pa, pb, qa, qb);
            pa -= (pa + pa) & -(long)(r & 1);
            pb -= (pb + pb) & -(long)(r & 1);
            qa -= (qa + qa) & -(long)(r >>> 1);
            qb -= (qb + qb) & -(long)(r >>> 1);
            FalconBigInt.co_reduce_mod(u0, u1, y, len, y0i, pa, pb, qa, qb);
            FalconBigInt.co_reduce_mod(v0, v1, x, len, x0i, pa, pb, qa, qb);
        }
        rc = a.num[0] ^ 1;
        for (j = 1; j < len; j++)
        {
            rc |= a.num[j];
        }
        boolean is_one = (int)((1 - ((rc | -rc) >> 31)) & x.num[0] & y.num[0]) == 1;
        return new FalconGcdRes(is_one, u0, v0);
    }

    /*
     * Add k*y*2^sc to this. The result is assumed to fit in the array of
     * size xlen (truncation is applied if necessary).
     * Scale factor 'sc' is provided as sch and scl, such that:
     *   sch = sc / 31
     *   scl = sc % 31
     * xlen MUST NOT be lower than ylen.
     *
     * this and y are both signed integers, using two's complement for
     * negative values.
     */
    void add_scaled_mul_small(int xlen, FalconBigInt y, int ylen, int k, int sch, int scl)
    {
        int u;
        int ysign, tw;
        int cc;
        if (ylen == 0)
        {
            return;
        }
        ysign = -(y.num[ylen - 1] >>> 30) >>> 1;
        tw = 0;
        cc = 0;
        for (u = sch; u < xlen; u++)
        {
            int v;
            int wy, wys, ccu;
            long z;
            v = u - sch;
            wy = v < ylen ? y.num[v] : ysign;
            wys = ((wy << scl) & 0x7FFFFFFF) | tw;
            tw = wy >>> (31 - scl);
            // note: these are casts to signed longs, and the whole thing is casted to unsigned
            // since we're in Java, the ending cast to unsigned does nothing
            z = (long)wys * (long)k + (long)this.num[u] + cc;
            this.num[u] = (int)z & 0x7FFFFFFF;
            ccu = (int)(z >> 31); // this is a signed shift
            cc = ccu;
        }
    }

    /*
     * Subtract y*2^sc from x. The result is assumed to fit in the array of
     * size xlen (truncation is applied if necessary).
     * Scale factor 'sc' is provided as sch and scl, such that:
     *   sch = sc / 31
     *   scl = sc % 31
     * xlen MUST NOT be lower than ylen.
     *
     * x[] and y[] are both signed integers, using two's complement for
     * negative values.
     */
    void sub_scaled(int xlen, FalconBigInt y, int ylen, int sch, int scl)
    {
        int u;
        int ysign, tw;
        int cc;
        if (ylen == 0)
        {
            return;
        }
        ysign = -(y.num[ylen - 1] >>> 30) >>> 1;
        tw = 0;
        cc = 0;
        for (u = sch; u < xlen; u++)
        {
            int v;
            int w, wy, wys;

            v = u - sch;
            wy = v < ylen ? y.num[v] : ysign;
            wys = ((wy << scl) & 0x7FFFFFFF) | tw;
            tw = wy >>> (31 - scl);

            w = this.num[u] - wys - cc;
            this.num[u] = w & 0x7FFFFFFF;
            cc = w >>> 31;
        }
    }

    /**
     * convert a one word signed big int to a signed int
     */
    int one_to_plain()
    {
        int w;
        w = this.num[0];
        w |= (w & 0x40000000) << 1;
        return w;
    }

    static void rebuild_CRT(int xx, int[] data, int xlen, int xstride, int num, FalconSmallPrime[] primes,
                            int normalise_signed, int tp, int[] tmp)
    {
        int u;
        int x;

        tmp[tp + 0] = primes[0].p;
        for (u = 1; u < xlen; u++)
        {
            /*
             * At the entry of each loop iteration:
             *  - the first u words of each array have been
             *    reassembled;
             *  - the first u words of tmp[] contains the
             * product of the prime moduli processed so far.
             *
             * We call 'q' the product of all previous primes.
             */
            int p, p0i, s, R2;
            int v;

            p = primes[u].p;
            s = primes[u].s;
            p0i = FalconCommon.modp_ninv31(p);
            R2 = FalconCommon.modp_R2(p, p0i);

            for (v = 0, x = xx; v < num; v++, x += xstride)
            {
                int xp, xq, xr;
                /*
                 * xp = the integer x modulo the prime p for this
                 *      iteration
                 * xq = (x mod q) mod p
                 */
                xp = data[x + u];
                xq = mod_small_unsigned(x, data, u, p, p0i, R2);

                /*
                 * New value is (x mod q) + q * (s * (xp - xq) mod p)
                 */
                xr = FalconCommon.modp_montymul(s, FalconCommon.modp_sub(xp, xq, p), p, p0i);
                add_mul_small(x, data, tp, tmp, u, xr);
            }

            /*
             * Update product of primes in tmp[].
             */
            tmp[tp + u] = mul_small(tp, tmp, u, p);
        }

        /*
         * Normalize the reconstructed values around 0.
         */
        if (normalise_signed == 1)
        {
            for (u = 0, x = xx; u < num; u++, x += xstride)
            {
                norm_zero(x, data, tp, tmp, xlen);
            }
        }
    }

    private static void norm_zero(int x, int[] xdata, int p, int[] pdata, int len)
    {
        int u;
        int r, bb;

        /*
         * Compare x with p/2. We use the shifted version of p, and p
         * is odd, so we really compare with (p-1)/2; we want to perform
         * the subtraction if and only if x > (p-1)/2.
         */
        r = 0;
        bb = 0;
        u = len;
        while (u-- > 0)
        {
            int wx, wp, cc;

            /*
             * Get the two words to compare in wx and wp (both over
             * 31 bits exactly).
             */
            wx = xdata[x + u];
            wp = (pdata[p + u] >>> 1) | (bb << 30);
            bb = pdata[p + u] & 1;

            /*
             * We set cc to -1, 0 or 1, depending on whether wp is
             * lower than, equal to, or greater than wx.
             */
            cc = wp - wx;
            cc = ((-cc) >>> 31) | -(cc >>> 31);

            /*
             * If r != 0 then it is either 1 or -1, and we keep its
             * value. Otherwise, if r = 0, then we replace it with cc.
             */
            r |= cc & ((r & 1) - 1);
        }

        /*
         * At this point, r = -1, 0 or 1, depending on whether (p-1)/2
         * is lower than, equal to, or greater than x. We thus want to
         * do the subtraction only if r = -1.
         */
        sub(x, xdata, p, pdata, len, r >>> 31);
    }

    static int sub(int a, int[] adata, int b, int[] bdata, int len, int ctl)
    {
        int u;
        int cc, m;

        cc = 0;
        m = -ctl;
        for (u = 0; u < len; u++)
        {
            int aw, w;

            aw = adata[a + u];
            w = aw - bdata[b + u] - cc;
            cc = w >>> 31;
            aw ^= ((w & 0x7FFFFFFF) ^ aw) & m;
            adata[a + u] = aw;
        }
        return cc;
    }

    static int mul_small(int m, int[] mdata, int mlen, int x)
    {
        int u;
        int cc;

        cc = 0;
        for (u = 0; u < mlen; u++)
        {
            long z;

            z = FalconCommon.uint_long(mdata[m + u]) * FalconCommon.uint_long(x) + cc;
            mdata[m + u] = (int)z & 0x7FFFFFFF;
            cc = (int)(z >> 31);
        }
        return cc;
    }

    static void add_mul_small(int x, int[] xdata, int y, int[] ydata, int len, int s)
    {
        int u;
        int cc;

        cc = 0;
        for (u = 0; u < len; u++)
        {
            int xw, yw;
            long z;

            xw = xdata[x + u];
            yw = ydata[y + u];
            z = FalconCommon.uint_long(yw) * FalconCommon.uint_long(s) + FalconCommon.uint_long(xw) + FalconCommon.uint_long(cc);
            xdata[x + u] = (int)z & 0x7FFFFFFF;
            cc = (int)(z >>> 31);
        }
        xdata[x + len] = cc;
    }

    static int mod_small_unsigned(int d, int[] data, int dlen, int p, int p0i, int R2)
    {
        int x;
        int u;

        /*
         * Algorithm: we inject words one by one, starting with the high
         * word. Each step is:
         *  - multiply x by 2^31
         *  - add new word
         */
        x = 0;
        u = dlen;
        while (u-- > 0)
        {
            int w;

            x = FalconCommon.modp_montymul(x, R2, p, p0i);
            w = data[d + u] - p;
            w += p & -(w >>> 31);
            x = FalconCommon.modp_add(x, w, p);
        }
        return x;
    }

    static int mod_small_signed(int d, int[] data, int dlen, int p, int p0i, int R2, int Rx)
    {
        int z;

        if (dlen == 0)
        {
            return 0;
        }
        z = mod_small_unsigned(d, data, dlen, p, p0i, R2);
        z = FalconCommon.modp_sub(z, Rx & -(data[d + dlen - 1] >>> 30), p);
        return z;
    }

    static boolean bezout(int u, int[] udata, int v, int[] vdata,
                          int x, int[] xdata, int y, int[] ydata,
                          int len, int tmp, int[] tmpdata)
    {
        int u0, u1, v0, v1, a, b;
        int x0i, y0i;
        int num, rc;
        int j;

        if (len == 0)
        {
            return false;
        }

        /*
         * u0 and v0 are the u and v result buffers; the four other
         * values (u1, v1, a and b) are taken from tmp[].
         */
        u0 = u;
        v0 = v;
        u1 = tmp;
        v1 = u1 + len;
        a = v1 + len;
        b = a + len;

        /*
         * We'll need the Montgomery reduction coefficients.
         */
        x0i = FalconCommon.modp_ninv31(xdata[x + 0]);
        y0i = FalconCommon.modp_ninv31(ydata[y + 0]);

        /*
         * Initialize a, b, u0, u1, v0 and v1.
         *  a = x   u0 = 1   v0 = 0
         *  b = y   u1 = y   v1 = x-1
         * Note that x is odd, so computing x-1 is easy.
         */
        // memcpy(a, x, len * sizeof *x);
        System.arraycopy(xdata, x, tmpdata, a, len);
        // memcpy(b, y, len * sizeof *y);
        System.arraycopy(ydata, y, tmpdata, b, len);
        // u0[0] = 1;
        udata[u0 + 0] = 1;
        // memset(u0 + 1, 0, (len - 1) * sizeof *u0);
        // memset(v0, 0, len * sizeof *v0);
        vdata[v0 + 0] = 0;
        for (int i = 1; i < len; i++)
        {
            udata[u0 + i] = 0;
            vdata[v0 + i] = 0;
        }
        // memcpy(u1, y, len * sizeof *u1);
        System.arraycopy(ydata, y, tmpdata, u1, len);
        // memcpy(v1, x, len * sizeof *v1);
        System.arraycopy(xdata, x, tmpdata, v1, len);
        // v1[0] --;
        tmpdata[v1 + 0]--;

        /*
         * Each input operand may be as large as 31*len bits, and we
         * reduce the total length by at least 30 bits at each iteration.
         */
        for (num = 62 * len + 30; num >= 30; num -= 30)
        {
            int c0, c1;
            int a0, a1, b0, b1;
            long a_hi, b_hi;
            int a_lo, b_lo;
            long pa, pb, qa, qb;
            int i;
            int r;

            /*
             * Extract the top words of a and b. If j is the highest
             * index >= 1 such that a[j] != 0 or b[j] != 0, then we
             * want (a[j] << 31) + a[j-1] and (b[j] << 31) + b[j-1].
             * If a and b are down to one word each, then we use
             * a[0] and b[0].
             */
            c0 = -1;
            c1 = -1;
            a0 = 0;
            a1 = 0;
            b0 = 0;
            b1 = 0;
            j = len;
            while (j-- > 0)
            {
                int aw, bw;

                aw = tmpdata[a + j];
                bw = tmpdata[b + j];
                a0 ^= (a0 ^ aw) & c0;
                a1 ^= (a1 ^ aw) & c1;
                b0 ^= (b0 ^ bw) & c0;
                b1 ^= (b1 ^ bw) & c1;
                c1 = c0;
                c0 &= (((aw | bw) + 0x7FFFFFFF) >>> 31) - 1;
            }

            /*
             * If c1 = 0, then we grabbed two words for a and b.
             * If c1 != 0 but c0 = 0, then we grabbed one word. It
             * is not possible that c1 != 0 and c0 != 0, because that
             * would mean that both integers are zero.
             */
            a1 |= a0 & c1;
            a0 &= ~c1;
            b1 |= b0 & c1;
            b0 &= ~c1;
            a_hi = (FalconCommon.uint_long(a0) << 31) + a1;
            b_hi = (FalconCommon.uint_long(b0) << 31) + b1;
            a_lo = tmpdata[a + 0];
            b_lo = tmpdata[b + 0];

            /*
             * Compute reduction factors:
             *
             *   a' = a*pa + b*pb
             *   b' = a*qa + b*qb
             *
             * such that a' and b' are both multiple of 2^31, but are
             * only marginally larger than a and b.
             */
            pa = 1;
            pb = 0;
            qa = 0;
            qb = 1;
            for (i = 0; i < 31; i++)
            {
                /*
                 * At each iteration:
                 *
                 *   a <- (a-b)/2 if: a is odd, b is odd, a_hi > b_hi
                 *   b <- (b-a)/2 if: a is odd, b is odd, a_hi <= b_hi
                 *   a <- a/2 if: a is even
                 *   b <- b/2 if: a is odd, b is even
                 *
                 * We multiply a_lo and b_lo by 2 at each
                 * iteration, thus a division by 2 really is a
                 * non-multiplication by 2.
                 */
                int rt, oa, ob, cAB, cBA, cA;
                long rz;

                /*
                 * rt = 1 if a_hi > b_hi, 0 otherwise.
                 */
                rz = b_hi - a_hi;
                rt = (int)((rz ^ ((a_hi ^ b_hi)
                    & (a_hi ^ rz))) >>> 63);

                /*
                 * cAB = 1 if b must be subtracted from a
                 * cBA = 1 if a must be subtracted from b
                 * cA = 1 if a must be divided by 2
                 *
                 * Rules:
                 *
                 *   cAB and cBA cannot both be 1.
                 *   If a is not divided by 2, b is.
                 */
                oa = (a_lo >> i) & 1;
                ob = (b_lo >> i) & 1;
                cAB = oa & ob & rt;
                cBA = oa & ob & ~rt;
                cA = cAB | (oa ^ 1);

                /*
                 * Conditional subtractions.
                 */
                a_lo -= b_lo & -cAB;
                a_hi -= b_hi & -FalconCommon.uint_long(cAB);
                pa -= qa & -(long)cAB;
                pb -= qb & -(long)cAB;
                b_lo -= a_lo & -cBA;
                b_hi -= a_hi & -FalconCommon.uint_long(cBA);
                qa -= pa & -(long)cBA;
                qb -= pb & -(long)cBA;

                /*
                 * Shifting.
                 */
                a_lo += a_lo & (cA - 1);
                pa += pa & ((long)cA - 1);
                pb += pb & ((long)cA - 1);
                a_hi ^= (a_hi ^ (a_hi >> 1)) & -FalconCommon.uint_long(cA);
                b_lo += b_lo & -cA;
                qa += qa & -(long)cA;
                qb += qb & -(long)cA;
                b_hi ^= (b_hi ^ (b_hi >> 1)) & (FalconCommon.uint_long(cA) - 1);
            }

            /*
             * Apply the computed parameters to our values. We
             * may have to correct pa and pb depending on the
             * returned value of zint_co_reduce() (when a and/or b
             * had to be negated).
             */
            r = co_reduce(a, tmpdata, b, tmpdata, len, pa, pb, qa, qb);
            pa -= (pa + pa) & -(long)(r & 1);
            pb -= (pb + pb) & -(long)(r & 1);
            qa -= (qa + qa) & -(long)(r >>> 1);
            qb -= (qb + qb) & -(long)(r >>> 1);
            co_reduce_mod(u0, udata, u1, tmpdata, y, ydata, len, y0i, pa, pb, qa, qb);
            co_reduce_mod(v0, vdata, v1, tmpdata, x, xdata, len, x0i, pa, pb, qa, qb);
        }

        /*
         * At that point, array a[] should contain the GCD, and the
         * results (u,v) should already be set. We check that the GCD
         * is indeed 1. We also check that the two operands x and y
         * are odd.
         */
        rc = tmpdata[a + 0] ^ 1;
        for (j = 1; j < len; j++)
        {
            rc |= tmpdata[a + j];
        }
        // System.out.println(String.format("    Finishing: %d",tmpdata[a]));
        // for (int i = 1; i < len; i++) {
        //     System.out.println(String.format("         %d",tmpdata[a+i]));
        // }
        // System.out.print(String.format("uint32_t x[] = {%d, ",tmpdata[x]));
        // for (int i = 1; i < len; i++) {
        //     System.out.print(String.format("%d",tmpdata[x+i]));
        //     if ( i == len-1) {
        //         System.out.print("};\n");
        //     } else {
        //         System.out.print(", ");
        //     }
        // }
        // System.out.print(String.format("uint32_t y[] = {%d, ",tmpdata[y]));
        // for (int i = 1; i < len; i++) {
        //     System.out.print(String.format("%d",tmpdata[y+i]));
        //     if ( i == len-1) {
        //         System.out.print("};\n");
        //     } else {
        //         System.out.print(", ");
        //     }
        // }
        return (int)((1 - ((rc | -rc) >>> 31)) & xdata[x + 0] & ydata[y + 0]) == 1;
    }

    static void co_reduce_mod(int a, int[] adata, int b, int[] bdata, int m, int[] mdata,
                              int len, int m0i, long xa, long xb, long ya, long yb)
    {

        int u;
        long cca, ccb;
        int fa, fb;

        /*
         * These are actually four combined Montgomery multiplications.
         */
        cca = 0;
        ccb = 0;
        fa = ((adata[a + 0] * (int)xa + bdata[b + 0] * (int)xb) * m0i) & 0x7FFFFFFF;
        fb = ((adata[a + 0] * (int)ya + bdata[b + 0] * (int)yb) * m0i) & 0x7FFFFFFF;
        for (u = 0; u < len; u++)
        {
            int wa, wb;
            long za, zb;

            wa = adata[a + u];
            wb = bdata[b + u];
            za = wa * xa + wb * xb
                + mdata[m + u] * FalconCommon.uint_long(fa) + cca;
            zb = wa * ya + wb * yb
                + mdata[m + u] * FalconCommon.uint_long(fb) + ccb;
            if (u > 0)
            {
                adata[a + u - 1] = (int)za & 0x7FFFFFFF;
                bdata[b + u - 1] = (int)zb & 0x7FFFFFFF;
            }
            cca = za >> 31;
            ccb = zb >> 31;
        }
        adata[a + len - 1] = (int)cca;
        bdata[b + len - 1] = (int)ccb;

        /*
         * At this point:
         *   -m <= a < 2*m
         *   -m <= b < 2*m
         * (this is a case of Montgomery reduction)
         * The top words of 'a' and 'b' may have a 32-th bit set.
         * We want to add or subtract the modulus, as required.
         */
        finish_mod(a, adata, len, m, mdata, (int)(cca >>> 63));
        finish_mod(b, bdata, len, m, mdata, (int)(ccb >>> 63));
    }

    static void finish_mod(int a, int[] adata, int len, int m, int[] mdata, int neg)
    {
        int u;
        int cc, xm, ym;

        /*
         * First pass: compare a (assumed nonnegative) with m. Note that
         * if the top word uses 32 bits, subtracting m must yield a
         * value less than 2^31 since a < 2*m.
         */
        cc = 0;
        for (u = 0; u < len; u++)
        {
            cc = (adata[a + u] - mdata[m + u] - cc) >>> 31;
        }

        /*
         * If neg = 1 then we must add m (regardless of cc)
         * If neg = 0 and cc = 0 then we must subtract m
         * If neg = 0 and cc = 1 then we must do nothing
         *
         * In the loop below, we conditionally subtract either m or -m
         * from a. Word xm is a word of m (if neg = 0) or -m (if neg = 1);
         * but if neg = 0 and cc = 1, then ym = 0 and it forces mw to 0.
         */
        xm = -neg >>> 1;
        ym = -(neg | (1 - cc));
        cc = neg;
        for (u = 0; u < len; u++)
        {
            int aw, mw;

            aw = adata[a + u];
            mw = (mdata[m + u] ^ xm) & ym;
            aw = aw - mw - cc;
            adata[a + u] = aw & 0x7FFFFFFF;
            cc = aw >>> 31;
        }
    }

    static int co_reduce(int a, int[] adata, int b, int[] bdata, int len, long xa, long xb, long ya,
                         long yb)
    {
        int u;
        long cca, ccb;
        int nega, negb;

        cca = 0;
        ccb = 0;
        for (u = 0; u < len; u++)
        {
            int wa, wb;
            long za, zb;

            wa = adata[a + u];
            wb = bdata[b + u];
            za = wa * xa + wb * xb + cca;
            zb = wa * ya + wb * yb + ccb;
            if (u > 0)
            {
                adata[a + u - 1] = (int)za & 0x7FFFFFFF;
                bdata[b + u - 1] = (int)zb & 0x7FFFFFFF;
            }
            cca = za >> 31;
            ccb = zb >> 31;
        }
        adata[a + len - 1] = (int)cca;
        bdata[b + len - 1] = (int)ccb;

        nega = (int)(cca >>> 63);
        negb = (int)(ccb >>> 63);
        negate(a, adata, len, nega);
        negate(b, bdata, len, negb);
        return nega | (negb << 1);
    }

    static void negate(int a, int[] adata, int len, int ctl)
    {
        int u;
        int cc, m;

        /*
         * If ctl = 1 then we flip the bits of a by XORing with
         * 0x7FFFFFFF, and we add 1 to the value. If ctl = 0 then we XOR
         * with 0 and add 0, which leaves the value unchanged.
         */
        cc = ctl;
        m = -ctl >>> 1;
        for (u = 0; u < len; u++)
        {
            int aw;

            aw = adata[a + u];
            aw = (aw ^ m) + cc;
            adata[a + u] = aw & 0x7FFFFFFF;
            cc = aw >>> 31;
        }
    }

    static void sub_scaled(int x, int[] xdata, int xlen, int y, int[] ydata, int ylen, int sch, int scl)
    {
        int u;
        int ysign, tw;
        int cc;

        if (ylen == 0)
        {
            return;
        }

        ysign = -(ydata[y + ylen - 1] >> 30) >> 1;
        tw = 0;
        cc = 0;
        for (u = sch; u < xlen; u++)
        {
            int v;
            int w, wy, wys;

            /*
             * Get the next word of y (scaled).
             */
            v = u - sch;
            wy = v < ylen ? ydata[y + v] : ysign;
            wys = ((wy << scl) & 0x7FFFFFFF) | tw;
            tw = wy >>> (31 - scl);

            w = xdata[x + u] - wys - cc;
            xdata[x + u] = w & 0x7FFFFFFF;
            cc = w >>> 31;
        }
    }

    static void add_scaled_mul_small(int x, int[] xdata, int xlen, int y, int[] ydata, int ylen, int k,
                                     int sch, int scl)
    {
        int u;
        int ysign, tw;
        int cc;

        if (ylen == 0)
        {
            return;
        }

        ysign = -(ydata[y + ylen - 1] >> 30) >> 1;
        tw = 0;
        cc = 0;
        for (u = sch; u < xlen; u++)
        {
            int v;
            int wy, wys, ccu;
            long z;

            /*
             * Get the next word of y (scaled).
             */
            v = u - sch;
            wy = v < ylen ? ydata[y + v] : ysign;
            wys = ((wy << scl) & 0x7FFFFFFF) | tw;
            tw = wy >>> (31 - scl);

            /*
             * The expression below does not overflow.
             */
            z = ((long)wys * (long)k + (long)xdata[x + u] + cc);
            xdata[x + u] = (int)z & 0x7FFFFFFF;

            /*
             * Right-shifting the signed value z would yield
             * implementation-defined results (arithmetic shift is
             * not guaranteed). However, we can cast to unsigned,
             * and get the next carry as an unsigned word. We can
             * then convert it back to signed by using the guaranteed
             * fact that 'int32_t' uses two's complement with no
             * trap representation or padding bit, and with a layout
             * compatible with that of 'uint32_t'.
             */
            ccu = (int)(z >>> 31);
            cc = ccu;
        }
    }

    static int one_to_plain(int x, int[] xdata)
    {
        int w;

        w = xdata[x];
        w |= (w & 0x40000000) << 1;
        return w;
    }

}
