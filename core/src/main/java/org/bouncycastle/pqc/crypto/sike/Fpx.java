package org.bouncycastle.pqc.crypto.sike;

import org.bouncycastle.util.Pack;

class Fpx
{
    private SIKEEngine engine;
    Fpx(SIKEEngine engine)
    {
        this.engine = engine;
    }

    // Multiprecision left shift by one.
    private void mp_shiftl1(long[] x, int nwords)
    {
        int i;
        for (i = nwords-1; i > 0; i--)
        {
            //SHIFTL
            x[i] = (x[i] << 1) ^ (x[i-1] >>> (Internal.RADIX - 1));
        }
        x[0] <<= 1;
    }

    // Cyclotomic squaring on elements of norm 1, using a^(p+1) = 1.
    protected void sqr_Fp2_cycl(long[][] a, long[] one)
    {
        long[] t0 = new long[engine.params.NWORDS_FIELD];

        fpaddPRIME(a[0], a[1], t0);    // t0 = a0 + a1
        fpsqr_mont(t0, t0);            // t0 = t0^2
        fpsubPRIME(t0, one, a[1]);     // a1 = t0 - 1
        fpsqr_mont(a[0], t0);          // t0 = a0^2
        fpaddPRIME(t0, t0, t0);        // t0 = t0 + t0
        fpsubPRIME(t0, one, a[0]);     // a0 = t0 - 1
    }

    // n-way simultaneous inversion using Montgomery's trick.
    // SECURITY NOTE: This function does not run in constant time.
    // Also, vec and out CANNOT be the same variable!
    protected void mont_n_way_inv(long[][][] vec, int n, long[][][] out)
    {
        long[][] t1 = new long[2][engine.params.NWORDS_FIELD];
        int i;

        fp2copy(vec[0], out[0]);                      // out[0] = vec[0]
        for (i = 1; i < n; i++)
        {
            fp2mul_mont(out[i-1], vec[i], out[i]);    // out[i] = out[i-1]*vec[i]
        }

        fp2copy(out[n-1], t1);                        // t1 = 1/out[n-1]
        fp2inv_mont_bingcd(t1);

        for (i = n-1; i >= 1; i--)
        {
            fp2mul_mont(out[i-1], t1, out[i]);        // out[i] = t1*out[i-1]
            fp2mul_mont(t1, vec[i], t1);              // t1 = t1*vec[i]
        }
        fp2copy(t1, out[0]);                          // out[0] = t1
    }


    // Copy a field element, c = a.
    protected void fpcopy(long[] a, int aOffset, long[] c)
    {
        int i;
        for (i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            c[i] = a[i + aOffset];
        }
    }

    // GF(p^2) addition without correction, c = a+b in GF(p^2).
    protected void mp2_add(long[][] a, long[][] b, long[][] c)
    {
        mp_add(a[0], b[0], c[0], engine.params.NWORDS_FIELD);
        mp_add(a[1], b[1], c[1], engine.params.NWORDS_FIELD);
    }

    // Modular correction, a = a in GF(p^2).
    protected void fp2correction(long[][] a)
    {
        fpcorrectionPRIME(a[0]);
        fpcorrectionPRIME(a[1]);
    }

    // Multiprecision addition, c = a+b, where lng(a) = lng(b) = nwords. Returns the carry bit.
    protected int mp_add(long[] a, long[] b, long[] c, int nwords)
    {
        int i, carry = 0;

        for (i = 0; i < nwords; i++)
        {
            //ADDC
            long tempReg = a[i] + carry;
            c[i] = b[i] + tempReg;
            carry = (is_digit_lessthan_ct(tempReg, carry) | is_digit_lessthan_ct(c[i], tempReg));
        }
        return carry;
    }

    // Multiprecision addition, c = a+b, where lng(a) = lng(b) = nwords. Returns the carry bit.
    private int mp_add(long[] a, int aOffset, long[] b, long[] c, int cOffset, int nwords)
    {
        int i, carry = 0;

        for (i = 0; i < nwords; i++)
        {
            //ADDC
            long tempReg = a[i + aOffset] + carry;
            c[i + cOffset] = b[i] + tempReg;
            carry = (is_digit_lessthan_ct(tempReg, carry) | is_digit_lessthan_ct(c[i + cOffset], tempReg));
        }
        return carry;
    }

    // Multiprecision addition, c = a+b, where lng(a) = lng(b) = nwords. Returns the carry bit.
    private int mp_add(long[] a, int aOffset, long[] b, int bOffset, long[] c, int cOffset, int nwords)
    {
        int i, carry = 0;

        for (i = 0; i < nwords; i++)
        {
            //ADDC
            long tempReg = a[i + aOffset] + carry;
            c[i + cOffset] = b[i + bOffset] + tempReg;
            carry = (is_digit_lessthan_ct(tempReg, carry) | is_digit_lessthan_ct(c[i + cOffset], tempReg));
        }
        return carry;
    }

    // Is x < y?
    private int is_digit_lessthan_ct(long x, long y)
    {
        return (int) ((x ^ ((x ^ y) | ((x - y) ^ y))) >>> (Internal.RADIX -1));
    }

    // Is x != 0?
    private int is_digit_nonzero_ct(long x)
    {
        return (int)((x | (0-x)) >>> (Internal.RADIX -1));
    }
    // Is x = 0?
    private int is_digit_zero_ct(long x)
    {
        return (1 ^ is_digit_nonzero_ct(x));
    }

    void fp2neg(long[][] a)
    { // GF(p^2) negation, a = -a in GF(p^2).
        fpnegPRIME(a[0]);
        fpnegPRIME(a[1]);
    }

    // Is x = 0? return 1 (TRUE) if condition is true, 0 (FALSE) otherwise.
    // SECURITY NOTE: This function does not run in constant-time.
    protected boolean is_felm_zero(long[] x)
    {
        int i;

        for (i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            if (x[i] != 0)
                return false;
        }
        return true;
    }

    // Is x < y? return 1 (TRUE) if condition is true, 0 (FALSE) otherwise.
    // SECURITY NOTE: This function does not run in constant-time.
    private boolean is_felm_lt(long[] x, long[] y)
    {
        for (int i = engine.params.NWORDS_FIELD-1; i >= 0; i--)
        {
            if (x[i] + Long.MIN_VALUE < y[i] + Long.MIN_VALUE)
            {
                return true;
            }
            else if (x[i] + Long.MIN_VALUE  > y[i] + Long.MIN_VALUE )
            {
                return false;
            }
        }
        return false;
    }

    // Is x even? return 1 (TRUE) if condition is true, 0 (FALSE) otherwise.
    private static boolean is_felm_even(long[] x)
    {
        return (x[0] & 1L) == 0L;
    }

    // Test if a is a square in GF(p^2) and return 1 if true, 0 otherwise
    // If a is a quadratic residue, s will be assigned with a partially computed square root of a
    protected boolean is_sqr_fp2(long[][] a, long[] s)
    {
        int i;
        long[] a0 = new long[engine.params.NWORDS_FIELD],
                a1 = new long[engine.params.NWORDS_FIELD],
                z = new long[engine.params.NWORDS_FIELD],
                temp = new long[engine.params.NWORDS_FIELD];

        fpsqr_mont(a[0],a0);
        fpsqr_mont(a[1],a1);
        fpaddPRIME(a0,a1,z);

        fpcopy(z, 0,s);
        for (i = 0; i < engine.params.OALICE_BITS - 2; i++)
        {
            fpsqr_mont(s, s);
        }
        for (i = 0; i < engine.params.OBOB_EXPON; i++)
        {
            fpsqr_mont(s, temp);
            fpmul_mont(s, temp, s);
        }
        fpsqr_mont(s,temp);          // s = z^((p+1)/4)
        fpcorrectionPRIME(temp);
        fpcorrectionPRIME(z);
        if (!subarrayEquals(temp, z, engine.params.NWORDS_FIELD))  // s^2 !=? z
        {
            return false;
        }

        return true;
    }

    // Partial Montgomery inversion via the binary GCD algorithm.
    private void fpinv_mont_bingcd_partial(long[] a, long[] x1, int[] k)
    {
        long[] u = new long[engine.params.NWORDS_FIELD],
               v = new long[engine.params.NWORDS_FIELD],
               x2 = new long[engine.params.NWORDS_FIELD];

        int cwords;  // Number of words necessary for x1, x2

        fpcopy(a, 0, u);
        fpcopy(engine.params.PRIME, 0, v);
        fpzero(x1); x1[0] = 1;
        fpzero(x2);
        k[0] = 0;

        while (!is_felm_zero(v))
        {
            cwords = ((k[0] + 1) / Internal.RADIX) + 1;
            if ((cwords < engine.params.NWORDS_FIELD))
            {
                if (is_felm_even(v))
                {
                    mp_shiftr1(v);
                    mp_shiftl1(x1, cwords);
                }
                else if (is_felm_even(u))
                {
                    mp_shiftr1(u);
                    mp_shiftl1(x2, cwords);
                }
                else if (!is_felm_lt(v, u))
                {
                    mp_sub(v, u, v, engine.params.NWORDS_FIELD);
                    mp_shiftr1(v);
                    mp_add(x1, x2, x2, cwords);
                    mp_shiftl1(x1, cwords);
                }
                else
                {
                    mp_sub(u, v, u, engine.params.NWORDS_FIELD);
                    mp_shiftr1(u);
                    mp_add(x1, x2, x1, cwords);
                    mp_shiftl1(x2, cwords);
                }
            }
            else
            {
                if (is_felm_even(v))
                {
                    mp_shiftr1(v);
                    mp_shiftl1(x1, engine.params.NWORDS_FIELD);
                }
                else if (is_felm_even(u))
                {
                    mp_shiftr1(u);
                    mp_shiftl1(x2, engine.params.NWORDS_FIELD);
                }
                else if (!is_felm_lt(v, u))
                {
                    mp_sub(v, u, v, engine.params.NWORDS_FIELD);
                    mp_shiftr1(v);
                    mp_add(x1, x2, x2, engine.params.NWORDS_FIELD);
                    mp_shiftl1(x1, engine.params.NWORDS_FIELD);
                }
                else
                {
                    mp_sub(u, v, u, engine.params.NWORDS_FIELD);
                    mp_shiftr1(u);
                    mp_add(x1, x2, x1, engine.params.NWORDS_FIELD);
                    mp_shiftl1(x2, engine.params.NWORDS_FIELD);
                }
            }
            k[0] += 1;
        }

        if (is_felm_lt(engine.params.PRIME, x1))
        {
            mp_sub(x1, engine.params.PRIME, x1, engine.params.NWORDS_FIELD);
        }
    }

    // Set up the value 2^mark.
    private void power2_setup(long[] x, int mark, int nwords)
    {
        int i;

        for (i = 0; i < nwords; i++) x[i] = 0;

        i = 0;
        while (mark >= 0)
        {
            if (mark < Internal.RADIX)
            {
                x[i] = (long)1 << mark;
            }
            mark -= Internal.RADIX;
            i += 1;
        }
    }


    // Field inversion via the binary GCD using Montgomery arithmetic, a = a^-1*r' mod p.
    // SECURITY NOTE: This function does not run in constant-time and is therefore only suitable for
    //                operations not involving any secret data.
    private void fpinv_mont_bingcd(long[] a)
    {
        long[] x = new long[engine.params.NWORDS_FIELD],
               t = new long[engine.params.NWORDS_FIELD];
        int[] k = new int[1];

        if (is_felm_zero(a))
            return;

        fpinv_mont_bingcd_partial(a, x, k);
        if (k[0] <= engine.params.MAXBITS_FIELD)
        {
            fpmul_mont(x, engine.params.Montgomery_R2, x);
            k[0] += engine.params.MAXBITS_FIELD;
        }
        fpmul_mont(x, engine.params.Montgomery_R2, x);
        power2_setup(t, 2*engine.params.MAXBITS_FIELD - k[0], engine.params.NWORDS_FIELD);
        fpmul_mont(x, t, a);
    }

    // GF(p^2) inversion using Montgomery arithmetic, a = (a0-i*a1)/(a0^2+a1^2)
    // This uses the binary GCD for inversion in fp and is NOT constant time!!!
    protected void fp2inv_mont_bingcd(long[][] a)
    {
        long[][] t1 = new long[2][engine.params.NWORDS_FIELD];

        fpsqr_mont(a[0], t1[0]);             // t10 = a0^2
        fpsqr_mont(a[1], t1[1]);             // t11 = a1^2
        fpaddPRIME(t1[0], t1[1], t1[0]);     // t10 = a0^2+a1^2


        fpinv_mont_bingcd(t1[0]);            // t10 = (a0^2+a1^2)^-1
        fpnegPRIME(a[1]);                         // a = a0-i*a1
        fpmul_mont(a[0], t1[0], a[0]);
        fpmul_mont(a[1], t1[0], a[1]);       // a = (a0-i*a1)*(a0^2+a1^2)^-1
    }

    // GF(p^2) division by two, c = a/2  in GF(p^2).
    protected void fp2div2(long[][] a, long[][] c)
    {
        fpdiv2_PRIME(a[0], c[0]);
        fpdiv2_PRIME(a[1], c[1]);
    }

    // Modular division by two, c = a/2 mod PRIME.
    // Input : a in [0, 2*PRIME-1]
    // Output: c in [0, 2*PRIME-1]
    private void fpdiv2_PRIME(long[] a, long[] c)
    {
        int i, carry = 0;
        long mask;

        mask = 0 - (a[0] & 1); // If a is odd compute a+PRIME
        for (i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            //ADDC
            long tempReg = a[i] + carry;
            c[i] = (engine.params.PRIME[i] & mask) + tempReg;
            carry = (is_digit_lessthan_ct(tempReg, carry) | is_digit_lessthan_ct(c[i], tempReg));
        }

        mp_shiftr1(c);
    }

    // Multiprecision subtraction with correction with 2*p, c = a-b+2p.
    private void mp_subPRIME_p2(long [] a, long[] b, long[] c)
    {
        int i, borrow = 0;

        for (i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            //SUBC
            long tempReg = a[i] - b[i];
            int borrowReg = (is_digit_lessthan_ct(a[i], b[i]) | (borrow & is_digit_zero_ct(tempReg)));
            c[i] = tempReg - (long)(borrow);
            borrow = borrowReg;
        }

        borrow = 0;
        for (i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            //ADDC
            long tempReg = c[i] + borrow;
            c[i] = engine.params.PRIMEx2[i] + tempReg;
            borrow = (is_digit_lessthan_ct(tempReg, borrow) | is_digit_lessthan_ct(c[i], tempReg));
        }
    }

    // Multiprecision subtraction with correction with 4*p, c = a-b+4p.
    private void mp_subPRIME_p4(long[] a, long[] b, long[] c)
    {
        int i, borrow = 0;

        for (i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            //SUBC
            long tempReg = a[i] - b[i];
            int borrowReg = (is_digit_lessthan_ct(a[i], b[i]) | (borrow & is_digit_zero_ct(tempReg)));
            c[i] = tempReg - (long)(borrow);
            borrow = borrowReg;

        }

        borrow = 0;
        for (i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            //ADDC
            long tempReg = c[i] + borrow;
            c[i] = engine.params.PRIMEx4[i] + tempReg;
            borrow = (is_digit_lessthan_ct(tempReg, borrow) | is_digit_lessthan_ct(c[i], tempReg));

        }
    }

    // Digit multiplication, digit * digit -> 2-digit result
    private void digit_x_digit(long a, long b, long[] c)
    {
        long al, ah, bl, bh, temp;
        long albl, albh, ahbl, ahbh, res1, res2, res3, carry;
        long mask_low = ((long)(-1)) >>> (8*4), mask_high = ((-1L)) << (8*4);

        al = a & mask_low;  // Low part
        ah = a >>> (8 * 4); // High part
        bl = b & mask_low;
        bh = b >>> (8 * 4);

        albl = al*bl;
        albh = al*bh;
        ahbl = ah*bl;
        ahbh = ah*bh;
        c[0] = albl & mask_low;             // C00

        res1 = albl >>> (8 * 4);
        res2 = ahbl & mask_low;
        res3 = albh & mask_low;
        temp = res1 + res2 + res3;
        carry = temp >>> (8 * 4);
        c[0] ^= temp << (8 * 4);            // C01

        res1 = ahbl >>> (8 * 4);
        res2 = albh >>> (8 * 4);
        res3 = ahbh & mask_low;
        temp = res1 + res2 + res3 + carry;
        c[1] = temp & mask_low;             // C10
        carry = temp & mask_high;
        c[1] ^= (ahbh & mask_high) + carry; // C11
    }

    // Efficient Montgomery reduction using comba and exploiting the special form of the prime PRIME.
    // mc = ma*R^-1 mod PRIMEx2, where R = 2^448.
    // If ma < 2^448*PRIME, the output mc is in the range [0, 2*PRIME-1].
    // ma is assumed to be in Montgomery representation.
    private void rdc_mont(long[] ma, long[] mc)
    {
        int i, j, carry, count = engine.params.PRIME_ZERO_WORDS;
        long t = 0, u = 0, v = 0, temp;
        long[] UV = new long[2];

        for (i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            mc[i] = 0;
        }

        for (i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            for (j = 0; j < i; j++)
            {
                if (j < (i-engine.params.PRIME_ZERO_WORDS+1))
                {
                    //MUL
                    digit_x_digit(mc[j], engine.params.PRIMEp1[i - j], UV);

                    //ADDC
                    temp = UV[0];
                    v += temp;
                    temp = UV[1] + is_digit_lessthan_ct(v, temp); // No overflow possible; high part of product < Long.MAX_VALUE 

                    //ADDC
                    u += temp;
                    t += is_digit_lessthan_ct(u, temp);
                }
            }

            //ADDC
            long tempReg = ma[i];
            v += tempReg;
            carry = is_digit_lessthan_ct(v, tempReg);

            //ADDC
            u += carry;
            carry &= is_digit_zero_ct(u);

            t += carry;
            mc[i] = v;
            v = u;
            u = t;
            t = 0;
        }

        for (i = engine.params.NWORDS_FIELD; i < 2*engine.params.NWORDS_FIELD-1; i++)
        {
            if (count > 0)
            {
                count -= 1;
            }
            for (j = i-engine.params.NWORDS_FIELD+1; j < engine.params.NWORDS_FIELD; j++)
            {
                if (j < (engine.params.NWORDS_FIELD-count))
                {
                    //MUL
                    digit_x_digit(mc[j], engine.params.PRIMEp1[i - j], UV);

                    //ADDC
                    temp = UV[0];
                    v += temp;
                    temp = UV[1] + is_digit_lessthan_ct(v, temp); // No overflow possible; high part of product < Long.MAX_VALUE 

                    //ADDC
                    u += temp;
                    t += is_digit_lessthan_ct(u, temp);
                }
            }

            //ADDC
            long tempReg = ma[i];
            v += tempReg;
            carry = is_digit_lessthan_ct(v, tempReg);

            //ADDC
            u += carry;
            carry &= is_digit_zero_ct(u);

            t += carry;
            mc[i - engine.params.NWORDS_FIELD] = v;
            v = u;
            u = t;
            t = 0;
        }

        //ADDC
        long tempReg = ma[2*engine.params.NWORDS_FIELD-1];
        v += tempReg;
        carry = is_digit_lessthan_ct(v, tempReg);
//        assert carry == 0;

        mc[engine.params.NWORDS_FIELD-1] = v;
//        assert u == 0;
//        assert t == 0;
    }

    protected static boolean subarrayEquals(long[] a, long[] b, int length)
    {
        for (int i = 0; i < length; i++)
        {
            if(a[i] != b[i])
                return false;
        }
        return true;
    }

    protected static boolean subarrayEquals(long[][] a, long[][] b, int length)
    {
        int nwords_feild = b[0].length;
        for (int i = 0; i < length; i++)
        {
            if(a[i/nwords_feild][i%nwords_feild] != b[i/nwords_feild][i%nwords_feild])
                return false;
        }
        return true;
    }

    protected static boolean subarrayEquals(long[][] a, long[][] b, int bOffset, int length)
    {
        int nwords_feild = b[0].length;
        for (int i = 0; i < length; i++)
        {
            if(a[i/nwords_feild][i%nwords_feild] != b[(i + bOffset)/nwords_feild][(i+bOffset)%nwords_feild])
                return false;
        }
        return true;
    }

    protected static boolean subarrayEquals(long[][] a, long[] b, int bOffset, int length)
    {
        int nwords_field = a[0].length;
        for (int i = 0; i < length; i++)
        {
            if(a[i/nwords_field][i%nwords_field] != b[(i + bOffset)])
                return false; //8316 -> 425529A64ABCAC1F
        }
        return true;
    }

    // Computes square roots of elements in (Fp2)^2 using Hamburg's trick.
    void sqrt_Fp2(long[][] u, long[][] y)
    {

        long[] t0 = new long[engine.params.NWORDS_FIELD],
               t1 = new long[engine.params.NWORDS_FIELD],
               t2 = new long[engine.params.NWORDS_FIELD],
               t3 = new long[engine.params.NWORDS_FIELD];

        int i;

        fpsqr_mont(u[0], t0);                   // t0 = a^2
        fpsqr_mont(u[1], t1);                   // t1 = b^2
        fpaddPRIME(t0, t1, t0);              // t0 = t0+t1
        fpcopy(t0, 0, t1);
        for (i = 0; i < engine.params.OALICE_BITS - 2; i++)
        {   // t = t3^((p+1)/4)
            fpsqr_mont(t1, t1);
        }
        for (i = 0; i < engine.params.OBOB_EXPON; i++)
        {
            fpsqr_mont(t1, t0);
            fpmul_mont(t1, t0, t1);
        }
        fpaddPRIME(u[0], t1, t0);         // t0 = a+t1
        fpdiv2_PRIME(t0, t0);             // t0 = t0/2
        fpcopy(t0, 0, t2);
        fpinv_chain_mont(t2);             // t2 = t0^((p-3)/4)
        fpmul_mont(t0, t2, t1);           // t1 = t2*t0
        fpmul_mont(t2, u[1], t2);         // t2 = t2*b
        fpdiv2_PRIME(t2, t2);             // t2 = t2/2
        fpsqr_mont(t1, t3);               // t3 = t1^2
        fpcorrectionPRIME(t0);
        fpcorrectionPRIME(t3);

        if (subarrayEquals(t0, t3, engine.params.NWORDS_FIELD))
        {
            fpcopy(t1, 0, y[0]);
            fpcopy(t2, 0, y[1]);
        }
        else
        {
            fpnegPRIME(t1);
            fpcopy(t2, 0, y[0]);
            fpcopy(t1, 0, y[1]);
        }
    }

    // GF(p^2) squaring using Montgomery arithmetic, c = a^2 in GF(p^2).
    // Inputs: a = a0+a1*i, where a0, a1 are in [0, 2*p-1]
    // Output: c = c0+c1*i, where c0, c1 are in [0, 2*p-1]
    protected void fp2sqr_mont(long[][] a, long[][] c)
    {
        long[] t1 = new long[engine.params.NWORDS_FIELD],
                t2 = new long[engine.params.NWORDS_FIELD],
                t3 = new long[engine.params.NWORDS_FIELD];

        mp_add(a[0], a[1], t1, engine.params.NWORDS_FIELD);   // t1 = a0+a1
        mp_subPRIME_p4(a[0], a[1], t2);           // t2 = a0-a1
        mp_add(a[0], a[0], t3, engine.params.NWORDS_FIELD);   // t3 = 2a0
        fpmul_mont(t1, t2, c[0]);               // c0 = (a0+a1)(a0-a1)
        fpmul_mont(t3, a[1], c[1]);             // c1 = 2a0*a1
    }

    // Modular addition, c = a+b mod PRIME.
    // Inputs: a, b in [0, 2*PRIME-1]
    // Output: c in [0, 2*PRIME-1]
    protected void fpaddPRIME(long[] a, long[] b, long[] c)
    {
        int i, carry = 0;
        long mask;

        for (i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            //ADDC
            long tempReg = a[i] + carry;
            c[i] = b[i] + tempReg;
            carry = (is_digit_lessthan_ct(tempReg, carry) | is_digit_lessthan_ct(c[i], tempReg));

        }

        carry = 0;
        for (i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            //SUBC
            long tempReg = c[i] - engine.params.PRIMEx2[i];
            int borrowReg = (is_digit_lessthan_ct(c[i], engine.params.PRIMEx2[i]) | (carry & is_digit_zero_ct(tempReg)));
            c[i] = tempReg - (long)(carry);
            carry = borrowReg;

        }
        mask = 0 - carry;

        carry = 0;
        for (i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            //ADDC
            long tempReg = c[i] + carry;
            c[i] = (engine.params.PRIMEx2[i] & mask) + tempReg;
            carry = (is_digit_lessthan_ct(tempReg, carry) | is_digit_lessthan_ct(c[i], tempReg));

        }
    }

    // Cyclotomic cubing on elements of norm 1, using a^(p+1) = 1.
    protected void cube_Fp2_cycl(long[][] a, long[] one)
    {
        long[] t0 = new long[engine.params.NWORDS_FIELD];

        fpaddPRIME(a[0], a[0], t0);    // t0 = a0 + a0
        fpsqr_mont(t0, t0);            // t0 = t0^2
        fpsubPRIME(t0, one, t0);       // t0 = t0 - 1
        fpmul_mont(a[1], t0, a[1]);    // a1 = t0*a1
        fpsubPRIME(t0, one, t0);
        fpsubPRIME(t0, one, t0);       // t0 = t0 - 2
        fpmul_mont(a[0], t0, a[0]);    // a0 = t0*a0
    }

    // Modular subtraction, c = a-b mod PRIME.
    // Inputs: a, b in [0, 2*PRIME-1]
    // Output: c in [0, 2*PRIME-1]
    protected void fpsubPRIME(long[] a, long[] b, int bOffset, long[] c)
    {
        int i, borrow = 0;
        long mask;

        for (i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            //SUBC
            long tempReg = a[i] - b[i + bOffset];
            int borrowReg = (is_digit_lessthan_ct(a[i], b[i + bOffset]) | (borrow & is_digit_zero_ct(tempReg)));
            c[i] = tempReg - (long)(borrow);
            borrow = borrowReg;
        }
        mask = 0 - borrow;

        borrow = 0;
        for (i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            //ADDC
            long tempReg = c[i] + borrow;
            c[i] = (engine.params.PRIMEx2[i] & mask) + tempReg;
            borrow = (is_digit_lessthan_ct(tempReg, borrow) | is_digit_lessthan_ct(c[i], tempReg));
        }
    }

    protected void fpsubPRIME(long[] a, int aOffset, long[] b, long[] c)
    {
        int i, borrow = 0;
        long mask;

        for (i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            //SUBC
            long tempReg = a[i + aOffset] - b[i];
            int borrowReg = (is_digit_lessthan_ct(a[i + aOffset], b[i]) | (borrow & is_digit_zero_ct(tempReg)));
            c[i] = tempReg - (long)(borrow);
            borrow = borrowReg;
        }
        mask = 0 - borrow;

        borrow = 0;
        for (i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            //ADDC
            long tempReg = c[i] + borrow;
            c[i] = (engine.params.PRIMEx2[i] & mask) + tempReg;
            borrow = (is_digit_lessthan_ct(tempReg, borrow) | is_digit_lessthan_ct(c[i], tempReg));
        }
    }

    protected void fpsubPRIME(long[] a, long[] b, long[] c)
    {
        int i, borrow = 0;
        long mask;

        for (i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            //SUBC
            long tempReg = a[i] - b[i];
            int borrowReg = (is_digit_lessthan_ct(a[i], b[i]) | (borrow & is_digit_zero_ct(tempReg)));
            c[i] = tempReg - (long)(borrow);
            borrow = borrowReg;
        }
        mask = 0 - borrow;

        borrow = 0;
        for (i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            //ADDC
            long tempReg = c[i] + borrow;
            c[i] = (engine.params.PRIMEx2[i] & mask) + tempReg;
            borrow = (is_digit_lessthan_ct(tempReg, borrow) | is_digit_lessthan_ct(c[i], tempReg));
        }
    }

    // Modular negation, a = -a mod PRIME.
    // Input/output: a in [0, 2*PRIME-1]
    protected void fpnegPRIME(long[] a)
    {
        int i, borrow = 0;

        for (i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            //SUBC
            long tempReg = engine.params.PRIMEx2[i] - a[i];
            int borrowReg = (is_digit_lessthan_ct(engine.params.PRIMEx2[i], a[i]) | (borrow & is_digit_zero_ct(tempReg)));
            a[i] = tempReg - (long)(borrow);
            borrow = borrowReg;
        }
    }

    // Conversion of a GF(p^2) element from Montgomery representation to standard representation,
    // c_i = ma_i*R^(-1) = a_i in GF(p^2).
    protected void from_fp2mont(long[][] ma, long[][] c)
    {
        from_mont(ma[0], c[0]);
        from_mont(ma[1], c[1]);
    }

    // Conversion of GF(p^2) element from Montgomery to standard representation, and encoding by removing leading 0 bytes
    protected void fp2_encode(long[][] x, byte[] enc, int encOffset)
    {
        long[][] t = new long[2][engine.params.NWORDS_FIELD];

        from_fp2mont(x, t);
        encode_to_bytes(t[0], enc, encOffset,engine.params.FP2_ENCODED_BYTES / 2);
        encode_to_bytes(t[1], enc, encOffset + engine.params.FP2_ENCODED_BYTES / 2, engine.params.FP2_ENCODED_BYTES / 2);
    }

    // Parse byte sequence back into GF(p^2) element, and conversion to Montgomery representation
    protected void fp2_decode(byte[] x, long[][] dec, int xOffset)
    {
        decode_to_digits(x, xOffset, dec[0], engine.params.FP2_ENCODED_BYTES / 2, engine.params.NWORDS_FIELD);
        decode_to_digits(x,xOffset + (engine.params.FP2_ENCODED_BYTES/2), dec[1], engine.params.FP2_ENCODED_BYTES / 2, engine.params.NWORDS_FIELD);
        to_fp2mont(dec, dec);
    }

    // Conversion of elements in Z_r to Montgomery representation, where the order r is up to NBITS_ORDER bits.
    protected void to_Montgomery_mod_order(long[] a, long[] mc, long[] order, long[] Montgomery_rprime, long[] Montgomery_Rprime)
    {
        Montgomery_multiply_mod_order(a, Montgomery_Rprime, mc, order, Montgomery_rprime);
    }

    // Montgomery multiplication modulo the group order, mc = ma*mb*r' mod order, where ma,mb,mc in [0, order-1].
    // ma, mb and mc are assumed to be in Montgomery representation.
    // The Montgomery constant r' = -r^(-1) mod 2^(log_2(r)) is the value "Montgomery_rprime", where r is the order.
    // Assume log_2(r) is a multiple of RADIX bits
    protected void Montgomery_multiply_mod_order(long[] ma, long[] mb, long[] mc, long[] order, long[] Montgomery_rprime)
    {
        int i, cout = 0, bout = 0;
        long mask;
        long[] P = new long[2*engine.params.NWORDS_ORDER],
               Q = new long[2*engine.params.NWORDS_ORDER],
               temp = new long[2*engine.params.NWORDS_ORDER];

        multiply(ma, mb, P, engine.params.NWORDS_ORDER);                 // P = ma * mb
        multiply(P, Montgomery_rprime, Q, engine.params.NWORDS_ORDER);   // Q = P * r' mod 2^(log_2(r))
        multiply(Q, order, temp, engine.params.NWORDS_ORDER);            // temp = Q * r
        cout = mp_add(P, temp, temp, 2*engine.params.NWORDS_ORDER);      // (cout, temp) = P + Q * r

        for (i = 0; i < engine.params.NWORDS_ORDER; i++)  // (cout, mc) = (P + Q * r)/2^(log_2(r))
        {
            mc[i] = temp[engine.params.NWORDS_ORDER+i];
        }

        // Final, constant-time subtraction
        bout = mp_sub(mc, order, mc, engine.params.NWORDS_ORDER);        // (cout, mc) = (cout, mc) - r
        mask = cout - bout;              // if (cout, mc) >= 0 then mask = 0x00..0, else if (cout, mc) < 0 then mask = 0xFF..F

        for (i = 0; i < engine.params.NWORDS_ORDER; i++)
        {               // temp = mask & r
            temp[i] = (order[i] & mask);
        }

        mp_add(mc, temp, mc, engine.params.NWORDS_ORDER);                //  mc = mc + (mask & r)
    }

    // Inversion of an odd integer modulo an even integer of the form 2^m.
    // Algorithm 3: Explicit Quadratic Modular inverse modulo 2^m from Dumas'12: https://arxiv.org/pdf/1209.6626.pdf
    // If the input is invalid (even), the function outputs c = a.
    protected void inv_mod_orderA(long[] a, long[] c)
    { 
        int i, f, s = 0;
        long[] am1 = new long[engine.params.NWORDS_ORDER],
                tmp1 = new long[engine.params.NWORDS_ORDER],
                tmp2 = new long[2*engine.params.NWORDS_ORDER],
                one = new long[engine.params.NWORDS_ORDER],
                order = new long[engine.params.NWORDS_ORDER];
        long mask = ((-1L) >>> (engine.params.NBITS_ORDER - engine.params.OALICE_BITS));

        order[engine.params.NWORDS_ORDER-1] = (1L << (64 - (engine.params.NBITS_ORDER - engine.params.OALICE_BITS)));  // Load most significant digit of Alice's order
        one[0] = 1;

        mp_sub(a, one, am1, engine.params.NWORDS_ORDER);                   // am1 = a-1

        if (((a[0] & 1) == 0) || (is_zero(am1, engine.params.NWORDS_ORDER)))
        {  // Check if the input is even or one
            copy_words(a, c, engine.params.NWORDS_ORDER);
            c[engine.params.NWORDS_ORDER-1] &= mask;                       // mod 2^m
        }
        else
        {
            mp_sub(order, am1, c, engine.params.NWORDS_ORDER);
            mp_add(c, one, c, engine.params.NWORDS_ORDER);                 // c = 2^m - a + 2

            copy_words(am1, tmp1, engine.params.NWORDS_ORDER);
            while ((tmp1[0] & 1L) == 0)
            {
                s += 1;
                mp_shiftr1(tmp1, engine.params.NWORDS_ORDER);
            }

            f = engine.params.OALICE_BITS / s;
            for (i = 1; i < f; i <<= 1)
            {
                multiply(am1, am1, tmp2, engine.params.NWORDS_ORDER);            // tmp2 = am1^2
                copy_words(tmp2, am1, engine.params.NWORDS_ORDER);
                am1[engine.params.NWORDS_ORDER-1] &= mask;                       // am1 = tmp2 mod 2^m
                mp_add(am1, one, tmp1, engine.params.NWORDS_ORDER);              // tmp1 = am1 + 1
                tmp1[engine.params.NWORDS_ORDER-1] &= mask;                      // mod 2^m
                multiply(c, tmp1, tmp2, engine.params.NWORDS_ORDER);             // c = c*tmp1
                copy_words(tmp2, c, engine.params.NWORDS_ORDER);
                c[engine.params.NWORDS_ORDER-1] &= mask;                         // mod 2^m
            }
        }
    }

    // Multiprecision comba multiply, c = a*b, where lng(a) = lng(b) = nwords.
    // NOTE: a and c CANNOT be the same variable!
    protected void multiply(long[] a, long[] b, long[] c, int nwords)
    {
        int i, j;
        long t = 0, u = 0, v = 0, temp;
        long[] UV = new long[2];

        for (i = 0; i < nwords; i++)
        {
            for (j = 0; j <= i; j++)
            {
                //MUL
                digit_x_digit(a[j], b[i - j], UV);

                //ADDC
                temp = UV[0];
                v += temp;
                temp = UV[1] + is_digit_lessthan_ct(v, temp); // No overflow possible; high part of product < Long.MAX_VALUE 

                //ADDC
                u += temp;
                t += is_digit_lessthan_ct(u, temp);
            }
            c[i] = v;
            v = u;
            u = t;
            t = 0;
        }
        for (i = nwords; i < 2*nwords-1; i++)
        {
            for (j = i-nwords+1; j < nwords; j++)
            {
                //MUL
                digit_x_digit(a[j], b[i - j], UV);

                //ADDC
                temp = UV[0];
                v += temp;
                temp = UV[1] + is_digit_lessthan_ct(v, temp); // No overflow possible; high part of product < Long.MAX_VALUE 

                //ADDC
                u += temp;
                t += is_digit_lessthan_ct(u, temp);
            }
            c[i] = v;
            v = u;
            u = t;
            t = 0;
        }
        c[2 * nwords - 1] = v;
//        assert u == 0;
//        assert t == 0;
    }

    // Is x = 0? return 1 (TRUE) if condition is true, 0 (FALSE) otherwise
    // SECURITY NOTE: This function does not run in constant time.
    private boolean is_zero_mod_order(long[] x)
    {
        int i;
        for (i = 0; i < engine.params.NWORDS_ORDER; i++)
        {
            if (x[i] != 0)
            {
                return false;
            }
        }
        return true;
    }

    // Is x even? return 1 (TRUE) if condition is true, 0 (FALSE) otherwise.
    private boolean is_even_mod_order(long[] x)
    {
        return ((x[0] & 1) ^ 1) == 1;
    }

    // Is x < y? return 1 (TRUE) if condition is true, 0 (FALSE) otherwise.
    // SECURITY NOTE: This function does not run in constant time.
    private boolean is_lt_mod_order(long[] x, long[] y)
    {
        int i;

        for (i = engine.params.NWORDS_ORDER-1; i >= 0; i--)
        {
            if (x[i] + Long.MIN_VALUE  < y[i] + Long.MIN_VALUE )
            {
                return true;
            }
            else if (x[i] + Long.MIN_VALUE  > y[i] + Long.MIN_VALUE )
            {
                return false;
            }
        }
        return false;
    }

    // Check if multiprecision element is zero.
    // SECURITY NOTE: This function does not run in constant time.
    private boolean is_zero(long[] a, int nwords)
    {
        for (int i = 0; i < nwords; i++)
        {
            if (a[i] != 0)
            {
                return false;
            }
        }
        return true;
    }


    // Partial Montgomery inversion modulo order.
    private void Montgomery_inversion_mod_order_bingcd_partial(long[] a, long[] x1, int[] k, long[] order)
    {
        long[] u = new long[engine.params.NWORDS_ORDER],
               v = new long[engine.params.NWORDS_ORDER],
               x2 = new long[engine.params.NWORDS_ORDER];
        int cwords;  // number of words necessary for x1, x2
    
        copy_words(a, u, engine.params.NWORDS_ORDER);
        copy_words(order, v, engine.params.NWORDS_ORDER);
        copy_words(x2, x1, engine.params.NWORDS_ORDER);
        x1[0] = 1;
        k[0] = 0;
    
        while (!is_zero_mod_order(v))
        {
            cwords = ((k[0] + 1) / Internal.RADIX) + 1;
            if ((cwords < engine.params.NWORDS_ORDER))
            {
                if (is_even_mod_order(v))
                {
                    mp_shiftr1(v, engine.params.NWORDS_ORDER);
                    mp_shiftl1(x1, cwords);
                }
                else if (is_even_mod_order(u))
                {
                    mp_shiftr1(u, engine.params.NWORDS_ORDER);
                    mp_shiftl1(x2, cwords);
                }
                else if (!is_lt_mod_order(v, u))
                {
                    mp_sub(v, u, v, engine.params.NWORDS_ORDER);
                    mp_shiftr1(v, engine.params.NWORDS_ORDER);
                    mp_add(x1, x2, x2, cwords);
                    mp_shiftl1(x1, cwords);
                }
                else
                {
                    mp_sub(u, v, u, engine.params.NWORDS_ORDER);
                    mp_shiftr1(u, engine.params.NWORDS_ORDER);
                    mp_add(x1, x2, x1, cwords);
                    mp_shiftl1(x2, cwords);
                }
            }
            else
            {
                if (is_even_mod_order(v))
                {
                    mp_shiftr1(v, engine.params.NWORDS_ORDER);
                    mp_shiftl1(x1, engine.params.NWORDS_ORDER);
                }
                else if (is_even_mod_order(u))
                {
                    mp_shiftr1(u, engine.params.NWORDS_ORDER);
                    mp_shiftl1(x2, engine.params.NWORDS_ORDER);
                }
                else if (!is_lt_mod_order(v, u))
                {
                    mp_sub(v, u, v, engine.params.NWORDS_ORDER);
                    mp_shiftr1(v, engine.params.NWORDS_ORDER);
                    mp_add(x1, x2, x2, engine.params.NWORDS_ORDER);
                    mp_shiftl1(x1, engine.params.NWORDS_ORDER);
                }
                else
                {
                    mp_sub(u, v, u, engine.params.NWORDS_ORDER);
                    mp_shiftr1(u, engine.params.NWORDS_ORDER);
                    mp_add(x1, x2, x1, engine.params.NWORDS_ORDER);
                    mp_shiftl1(x2, engine.params.NWORDS_ORDER);
                }
            }
            k[0] += 1;
        }
    
        if (is_lt_mod_order(order, x1))
        {
            mp_sub(x1, order, x1, engine.params.NWORDS_ORDER);
        }
    }

    // Montgomery inversion modulo order, c = a^(-1)*R mod order.
    protected void Montgomery_inversion_mod_order_bingcd(long[] a, long[] c, long[] order, long[] Montgomery_rprime, long[] Montgomery_Rprime)
    {
        long[] x = new long[engine.params.NWORDS_ORDER],
               t = new long[engine.params.NWORDS_ORDER];
        int[] k = new int[1];

        if (is_zero(a, engine.params.NWORDS_ORDER))
        {
            copy_words(t, c, engine.params.NWORDS_ORDER);
            return;
        }

        Montgomery_inversion_mod_order_bingcd_partial(a, x, k, order);
        if (k[0] <= engine.params.NBITS_ORDER)
        {
            Montgomery_multiply_mod_order(x, Montgomery_Rprime, x, order, Montgomery_rprime);
            k[0] += engine.params.NBITS_ORDER;
        }

        Montgomery_multiply_mod_order(x, Montgomery_Rprime, x, order, Montgomery_rprime);
        power2_setup(t, 2*engine.params.NBITS_ORDER - k[0], engine.params.NWORDS_ORDER);
        Montgomery_multiply_mod_order(x, t, c, order, Montgomery_rprime);
    }

    // Conversion of elements in Z_r from Montgomery to standard representation, where the order is up to NBITS_ORDER bits.
    protected void from_Montgomery_mod_order(long[] ma, long[] c, long[] order, long[] Montgomery_rprime)
    {
        long[] one = new long[engine.params.NWORDS_ORDER];
        one[0] = 1;

        Montgomery_multiply_mod_order(ma, one, c, order, Montgomery_rprime);
    }

    // Computes the input modulo 3
    // The input is assumed to be NWORDS_ORDER long
    protected int mod3(long[] a)
    {
        long temp;
        int r = 0;
        int[] val = Pack.littleEndianToInt(Pack.longToLittleEndian(a), 0, a.length*2);

        for (int i = (2*engine.params.NWORDS_ORDER-1); i >= 0; i--)
        {
            temp = ((long)r << (4*8)) | ((long)val[i]) & 0x00000000ffffffffL;
            r = (int)(temp % 3);
        }

    return r;
}

    // Conversion of a GF(p^2) element to Montgomery representation,
    // mc_i = a_i*R^2*R^(-1) = a_i*R in GF(p^2).
    protected void to_fp2mont(long[][] a, long[][] mc)
    {
        to_mont(a[0], mc[0]);
        to_mont(a[1], mc[1]);
    }

    // Conversion to Montgomery representation,
    // mc = a*R^2*R^(-1) mod p = a*R mod p, where a in [0, p-1].
    // The Montgomery constant R^2 mod p is the global value "Montgomery_R2".
    private void to_mont(long[] a, long[] mc)
    {
        fpmul_mont(a, engine.params.Montgomery_R2, mc);
    }


    // Modular correction to reduce field element a in [0, 2*PRIME-1] to [0, PRIME-1].
    protected void fpcorrectionPRIME(long[] a)
    {
        int i, borrow = 0;
        long mask;

        for (i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            //SUBC
            long tempReg = a[i] - engine.params.PRIME[i];
            int borrowReg = (is_digit_lessthan_ct(a[i], engine.params.PRIME[i]) | (borrow & is_digit_zero_ct(tempReg)));
            a[i] = tempReg - (long)(borrow);
            borrow = borrowReg;
        }
        mask = 0 - borrow;

        borrow = 0;
        for (i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            //ADDC
            long tempReg = a[i] + borrow;
            a[i] = (engine.params.PRIME[i] & mask) + tempReg;
            borrow = (is_digit_lessthan_ct(tempReg, borrow) | is_digit_lessthan_ct(a[i], tempReg));
        }
    }

    protected byte cmp_f2elm(long[][] x, long[][] y)
    { // Comparison of two GF(p^2) elements in constant time. 
        // Is x != y? return -1 if condition is true, 0 otherwise.
        long[][] a = new long[2][engine.params.NWORDS_FIELD],
                 b = new long[2][engine.params.NWORDS_FIELD];
        byte r = 0;

        fp2copy(x, a);
        fp2copy(y, b);
        fp2correction(a);
        fp2correction(b);

        for (int i = engine.params.NWORDS_FIELD-1; i >= 0; i--)
        {
            r |= (a[0][i] ^ b[0][i]) | (a[1][i] ^ b[1][i]);
        }

        return (byte) ((-(byte)r) >>> (8-1));
    }


    // Encoding digits to bytes according to endianness
    protected void encode_to_bytes(long[] x, byte[] enc, int encOffset, int nbytes)
    {
        byte[] test = new byte[((nbytes*4+7)&~7)];
        Pack.longToLittleEndian(x, test, 0);
        System.arraycopy(test, 0, enc, encOffset, nbytes);
    }

    // Decoding bytes to digits according to endianness
    protected void decode_to_digits(byte[] x, int xOffset, long[] dec, int nbytes, int ndigits)
    {
        // x -> dec
        dec[ndigits - 1] = 0;
        byte[] temp = new byte[(nbytes+7)&~7];
        System.arraycopy(x, xOffset, temp, 0, nbytes);
        Pack.littleEndianToLong(temp, 0, dec);

    }

    // r = a - b*i where v = a + b*i
    protected void fp2_conj(long[][] v, long[][] r)
    {
        fpcopy(v[0], 0, r[0]);
        fpcopy(v[1], 0, r[1]);

        if(!is_felm_zero(r[1]))
        {
            fpnegPRIME(r[1]);
        }
    }




    // Conversion from Montgomery representation to standard representation,
    // c = ma*R^(-1) mod p = a mod p, where ma in [0, p-1].
    private void from_mont(long[] ma, long[] c)
    {
        long[] one = new long[engine.params.NWORDS_FIELD];

        one[0] = 1;
        fpmul_mont(ma, one, c);
        fpcorrectionPRIME(c);
    }

    // Multiprecision right shift by one.
    private void mp_shiftr1(long[] x)
    {
        int i;

        for (i = 0; i < engine.params.NWORDS_FIELD-1; i++)
        {
            //SHIFTR
            x[i] = (x[i] >>> 1) ^ (x[i+1] << (Internal.RADIX - 1));
        }
        x[engine.params.NWORDS_FIELD-1] >>>= 1;
    }

    private void mp_shiftr1(long[] x, int nwords)
    {
        int i;

        for (i = 0; i < nwords-1; i++)
        {
            //SHIFTR
            x[i] = (x[i] >>> 1) ^ (x[i+1] << (Internal.RADIX - 1));
        }
        x[nwords-1] >>>= 1;
    }

    // Copy a GF(p^2) element, c = a.
    protected void fp2copy(long[][] a, long[][] c)
    {
        fpcopy(a[0], 0, c[0]);
        fpcopy(a[1], 0, c[1]);
    }

    // Copy a GF(p^2) element, c = a.
    protected void fp2copy(long[][] a, int aOffset, long[][] c)
    {
        fpcopy(a[0 + aOffset], 0, c[0]);
        fpcopy(a[1 + aOffset], 0, c[1]);
    }

    // Copy a GF(p^2) element, c = a.
    protected void fp2copy(long[] a, int aOffset, long[][] c)
    {
        fpcopy(a, aOffset, c[0]);
        fpcopy(a, aOffset + engine.params.NWORDS_FIELD, c[1]);
    }

    // Zero a field element, a = 0.
    protected void fpzero(long[] a)
    {
        int i;

        for (i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            a[i] = 0;
        }
    }

    // GF(p^2) subtraction with correction with 2*p, c = a-b+2p in GF(p^2).
    protected void mp2_sub_p2(long[][] a, long[][] b, long[][] c)
    {
        //todo/org : make fp class and change this to generic mp_sub_p2
        mp_subPRIME_p2(a[0], b[0], c[0]);
        mp_subPRIME_p2(a[1], b[1], c[1]);
    }

    // Multiprecision comba multiply, c = a*b, where lng(a) = lng(b) = nwords.
    protected void mp_mul(long[] a, long[] b, long[] c, int nwords)
    {
        int i, j;
        long t = 0, u = 0, v = 0, temp;
        long[] UV = new long[2];

        for (i = 0; i < nwords; i++)
        {
            for (j = 0; j <= i; j++)
            {
                //MUL
                digit_x_digit(a[j], b[i - j], UV);

                //ADDC
                temp = UV[0];
                v += temp;
                temp = UV[1] + is_digit_lessthan_ct(v, temp); // No overflow possible; high part of product < Long.MAX_VALUE 

                //ADDC
                u += temp;
                t += is_digit_lessthan_ct(u, temp);
            }
            c[i] = v;
            v = u;
            u = t;
            t = 0;
        }

        for (i = nwords; i < 2*nwords-1; i++)
        {
            for (j = i-nwords+1; j < nwords; j++)
            {
                //MUL
                digit_x_digit(a[j], b[i - j], UV);

                //ADDC
                temp = UV[0];
                v += temp;
                temp = UV[1] + is_digit_lessthan_ct(v, temp); // No overflow possible; high part of product < Long.MAX_VALUE 

                //ADDC
                u += temp;
                t += is_digit_lessthan_ct(u, temp);
            }
            c[i] = v;
            v = u;
            u = t;
            t = 0;
        }
        c[2 * nwords - 1] = v;
//        assert u == 0;
//        assert t == 0;
    }

    // Multiprecision comba multiply, c = a*b, where lng(a) = lng(b) = nwords.
    protected void mp_mul(long[] a, int aOffset, long[] b, long[] c, int nwords)
    {
        int i, j;
        long t = 0, u = 0, v = 0, temp;
        long[] UV = new long[2];

        for (i = 0; i < nwords; i++)
        {
            for (j = 0; j <= i; j++)
            {
                //MUL
                digit_x_digit(a[j + aOffset], b[i - j], UV);

                //ADDC
                temp = UV[0];
                v += temp;
                temp = UV[1] + is_digit_lessthan_ct(v, temp); // No overflow possible; high part of product < Long.MAX_VALUE 

                //ADDC
                u += temp;
                t += is_digit_lessthan_ct(u, temp);
            }
            c[i] = v;
            v = u;
            u = t;
            t = 0;
        }

        for (i = nwords; i < 2*nwords-1; i++)
        {
            for (j = i-nwords+1; j < nwords; j++)
            {
                //MUL
                digit_x_digit(a[j + aOffset], b[i - j], UV);

                //ADDC
                temp = UV[0];
                v += temp;
                temp = UV[1] + is_digit_lessthan_ct(v, temp); // No overflow possible; high part of product < Long.MAX_VALUE 

                //ADDC
                u += temp;
                t += is_digit_lessthan_ct(u, temp);
            }
            c[i] = v;
            v = u;
            u = t;
            t = 0;
        }
        c[2 * nwords - 1] = v;
//        assert u == 0;
//        assert t == 0;
    }

    // GF(p^2) multiplication using Montgomery arithmetic, c = a*b in GF(p^2).
    // Inputs: a = a0+a1*i and b = b0+b1*i, where a0, a1, b0, b1 are in [0, 2*p-1]
    // Output: c = c0+c1*i, where c0, c1 are in [0, 2*p-1]
    protected void fp2mul_mont(long[][] a, long[][] b, long[][] c)
    {
        long[] t1 = new long[engine.params.NWORDS_FIELD],
               t2 = new long[engine.params.NWORDS_FIELD];
        long[] tt1 = new long[2*engine.params.NWORDS_FIELD],
               tt2 = new long[2*engine.params.NWORDS_FIELD],
               tt3 = new long[2*engine.params.NWORDS_FIELD];

        mp_add(a[0], a[1], t1, engine.params.NWORDS_FIELD);            // t1 = a0+a1
        mp_add(b[0], b[1], t2, engine.params.NWORDS_FIELD);            // t2 = b0+b1
        mp_mul(a[0], b[0], tt1, engine.params.NWORDS_FIELD);           // tt1 = a0*b0
        mp_mul(a[1], b[1], tt2, engine.params.NWORDS_FIELD);           // tt2 = a1*b1
        mp_mul(t1, t2, tt3, engine.params.NWORDS_FIELD);               // tt3 = (a0+a1)*(b0+b1)
        mp_dblsubfast(tt1, tt2, tt3);                    // tt3 = (a0+a1)*(b0+b1) - a0*b0 - a1*b1
        mp_subaddfast(tt1, tt2, tt1);                    // tt1 = a0*b0 - a1*b1 + p*2^MAXBITS_FIELD if a0*b0 - a1*b1 < 0, else tt1 = a0*b0 - a1*b1
        rdc_mont(tt3, c[1]);                             // c[1] = (a0+a1)*(b0+b1) - a0*b0 - a1*b1
        rdc_mont(tt1, c[0]);                             // c[0] = a0*b0 - a1*b1
    }

    protected void fp2mul_mont(long[][] a, long[][] b, int bOffset, long[][] c)
    {

//        System.out.print("b: ");
//        for (int di = 0; di < 2; di++){for (int dj = 0; dj < engine.params.NWORDS_FIELD; dj++)
//        {System.out.printf("%016x ", b[di + bOffset][dj] );}System.out.println();}

        long[] t1 = new long[engine.params.NWORDS_FIELD],
                t2 = new long[engine.params.NWORDS_FIELD];
        long[] tt1 = new long[2*engine.params.NWORDS_FIELD],
                tt2 = new long[2*engine.params.NWORDS_FIELD],
                tt3 = new long[2*engine.params.NWORDS_FIELD];

        mp_add(a[0], a[1], t1, engine.params.NWORDS_FIELD);            // t1 = a0+a1
        mp_add(b[0 + bOffset], b[bOffset + 1], t2, engine.params.NWORDS_FIELD);            // t2 = b0+b1
        mp_mul(a[0], b[bOffset + 0], tt1, engine.params.NWORDS_FIELD);           // tt1 = a0*b0
        mp_mul(a[1], b[bOffset + 1], tt2, engine.params.NWORDS_FIELD);           // tt2 = a1*b1
        mp_mul(t1, t2, tt3, engine.params.NWORDS_FIELD);               // tt3 = (a0+a1)*(b0+b1)
        mp_dblsubfast(tt1, tt2, tt3);                    // tt3 = (a0+a1)*(b0+b1) - a0*b0 - a1*b1
        mp_subaddfast(tt1, tt2, tt1);                    // tt1 = a0*b0 - a1*b1 + p*2^MAXBITS_FIELD if a0*b0 - a1*b1 < 0, else tt1 = a0*b0 - a1*b1
        rdc_mont(tt3, c[1]);                             // c[1] = (a0+a1)*(b0+b1) - a0*b0 - a1*b1
        rdc_mont(tt1, c[0]);                             // c[0] = a0*b0 - a1*b1
    }

    protected void fp2mul_mont(long[][] a, long[] b, int bOffset, long[][] c)
    {
        long[] t1 = new long[engine.params.NWORDS_FIELD],
                t2 = new long[engine.params.NWORDS_FIELD];
        long[] tt1 = new long[2*engine.params.NWORDS_FIELD],
                tt2 = new long[2*engine.params.NWORDS_FIELD],
                tt3 = new long[2*engine.params.NWORDS_FIELD];

        mp_add(a[0], a[1], t1, engine.params.NWORDS_FIELD);            // t1 = a0+a1
        mp_add(b, bOffset, b, bOffset + engine.params.NWORDS_FIELD, t2,  0,engine.params.NWORDS_FIELD);            // t2 = b0+b1
        mp_mul(b, bOffset, a[0], tt1, engine.params.NWORDS_FIELD);           // tt1 = a0*b0
        mp_mul(b,bOffset + engine.params.NWORDS_FIELD, a[1], tt2, engine.params.NWORDS_FIELD);           // tt2 = a1*b1
        mp_mul(t1, t2, tt3, engine.params.NWORDS_FIELD);               // tt3 = (a0+a1)*(b0+b1)
        mp_dblsubfast(tt1, tt2, tt3);                    // tt3 = (a0+a1)*(b0+b1) - a0*b0 - a1*b1
        mp_subaddfast(tt1, tt2, tt1);                    // tt1 = a0*b0 - a1*b1 + p*2^MAXBITS_FIELD if a0*b0 - a1*b1 < 0, else tt1 = a0*b0 - a1*b1
        rdc_mont(tt3, c[1]);                             // c[1] = (a0+a1)*(b0+b1) - a0*b0 - a1*b1
        rdc_mont(tt1, c[0]);                             // c[0] = a0*b0 - a1*b1
    }

    // Multiprecision subtraction, c = c-a-b, where lng(a) = lng(b) = 2*engine.params.NWORDS_FIELD.
    private void mp_dblsubfast(long[] a, long[] b, long[] c)
    {
        mp_sub(c, a, c, 2*engine.params.NWORDS_FIELD);
        mp_sub(c, b, c, 2*engine.params.NWORDS_FIELD);
    }

    // Multiprecision subtraction, c = a-b, where lng(a) = lng(b) = nwords. Returns the borrow bit.
    protected int mp_sub(long[] a, long[] b, long[] c, int nwords)
    {
        int i, borrow = 0;
    
        for (i = 0; i < nwords; i++)
        {
            //SUBC
            long tempReg = a[i] - b[i];
//            System.out.printf("%016x ", tempReg);
            int borrowReg = (is_digit_lessthan_ct(a[i], b[i]) | (borrow & is_digit_zero_ct(tempReg)));
            c[i] = tempReg - (long)(borrow);
            borrow = borrowReg;
        }
//        System.out.println();
        return borrow;
    }

    // Is x < y? return 1 (TRUE) if condition is true, 0 (FALSE) otherwise.
    // SECURITY NOTE: This function does not run in constant-time.
    protected boolean is_orderelm_lt(long[] x, long[] y)
    {

        for (int i = engine.params.NWORDS_ORDER-1; i >= 0; i--)
        {

            if (x[i] + Long.MIN_VALUE < y[i] + Long.MIN_VALUE)
            {
                return true;
            }
            else if (x[i] + Long.MIN_VALUE  > y[i] + Long.MIN_VALUE )
            {
                return false;
            }
        }
        return false;
    }


    // Multiprecision subtraction followed by addition with p*2^MAXBITS_FIELD, c = a-b+(p*2^MAXBITS_FIELD) if a-b < 0, otherwise c=a-b. 
    private void mp_subaddfast(long[] a, long[] b, long[] c)
    {
        long[] t1 = new long[engine.params.NWORDS_FIELD];
    
        long mask = 0 - (long) mp_sub(a, b, c, 2*engine.params.NWORDS_FIELD);
        for (int i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            t1[i] = engine.params.PRIME[i] & mask;
        }
        mp_add(c, engine.params.NWORDS_FIELD, t1, c, engine.params.NWORDS_FIELD, engine.params.NWORDS_FIELD);
    }

    // Multiprecision squaring, c = a^2 mod p.
    protected void fpsqr_mont(long[] ma, long[] mc)
    {
        long[] temp = new long[2*engine.params.NWORDS_FIELD];

        mp_mul(ma, ma, temp, engine.params.NWORDS_FIELD);
        rdc_mont(temp, mc);
    }

    // Field inversion using Montgomery arithmetic, a = a^(-1)*R mod p.
    private void fpinv_mont(long[] a)
    {
        long[] tt = new long[engine.params.NWORDS_FIELD];

        fpcopy(a, 0, tt);
        fpinv_chain_mont(tt);
        fpsqr_mont(tt, tt);
        fpsqr_mont(tt, tt);
        fpmul_mont(a, tt, a);
    }

    // GF(p^2) inversion using Montgomery arithmetic, a = (a0-i*a1)/(a0^2+a1^2).
    protected void fp2inv_mont(long[][] a)
    {
        long[][] t1 = new long[2][engine.params.NWORDS_FIELD];

        fpsqr_mont(a[0], t1[0]);                 // t10 = a0^2
        fpsqr_mont(a[1], t1[1]);                 // t11 = a1^2
        fpaddPRIME(t1[0], t1[1], t1[0]);           // t10 = a0^2+a1^2
        fpinv_mont(t1[0]);                       // t10 = (a0^2+a1^2)^-1
        fpnegPRIME(a[1]);                          // a = a0-i*a1
        fpmul_mont(a[0], t1[0], a[0]);
        fpmul_mont(a[1], t1[0], a[1]);           // a = (a0-i*a1)*(a0^2+a1^2)^-1
    }

    // Computes a = 3*a
    // The input is assumed to be OBOB_BITS-2 bits long and stored in SECRETKEY_B_BYTES
    protected void mul3(byte[] a)
    {
        long[] temp1 = new long[engine.params.NWORDS_ORDER],
               temp2 = new long[engine.params.NWORDS_ORDER];

        decode_to_digits(a, 0, temp1, engine.params.SECRETKEY_B_BYTES, engine.params.NWORDS_ORDER);
        mp_add(temp1, temp1, temp2, engine.params.NWORDS_ORDER);               // temp2 = 2*a
        mp_add(temp1, temp2, temp1, engine.params.NWORDS_ORDER);               // temp1 = 3*a
        encode_to_bytes(temp1,  a, 0, engine.params.SECRETKEY_B_BYTES);
    }

    // Compare two byte arrays in constant time.
    // Returns 0 if the byte arrays are equal, -1 otherwise.
    protected byte ct_compare(byte[] a, byte[] b, int len)
    {
        byte r = 0;

        for (int i = 0; i < len; i++)
        {
            r |= a[i] ^ b[i];
        }
        return (byte)((-(byte)r) >>> 7);
    }

    // Conditional move in constant time.
    // If selector = -1 then load r with a, else if selector = 0 then keep r.
    protected void ct_cmov(byte[] r, byte[] a, int len, byte selector)
    {
        for (int i = 0; i < len; i++)
        {
            r[i] ^= selector & (a[i] ^ r[i]);
        }
    }

    // Copy wordsize digits, c = a, where lng(a) = nwords.
    protected void copy_words(long[] a, long[] c, int nwords)
    {
        int i;
        for (i = 0; i < nwords; i++)
        {
            c[i] = a[i];
        }
    }

    // c = (2^k)*a
    protected void fp2shl(long[][] a, int k, long[][] c)
    {
        fp2copy(a, c);
        for (int j = 0; j < k; j++)
        {
            fp2add(c, c, c);
        }
    }

    // Copy wordsize digits, c = a, where lng(a) = nwords.
    protected void copy_words(PointProj a, PointProj c)
    {
        int i;
        for (i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            c.X[0][i] = a.X[0][i];
            c.X[1][i] = a.X[1][i];
            c.Z[0][i] = a.Z[0][i];
            c.Z[1][i] = a.Z[1][i];
        }
    }

    // Modular negation, a = -a mod p.
    // Input/output: a in [0, 2*p-1]
    void Montgomery_neg(long[] a, long[] order)
    {
        int i, borrow = 0;

        for (i = 0; i < engine.params.NWORDS_ORDER; i++)
        {
            //SUBC
            long tempReg = order[i] - a[i];
            int borrowReg = (is_digit_lessthan_ct(order[i], a[i]) | (borrow & is_digit_zero_ct(tempReg)));
            a[i] = tempReg - (long)(borrow);
            borrow = borrowReg;

        }
    }


    // GF(p^2) addition, c = a+b in GF(p^2).
    protected void fp2add(long[][] a, long[][] b, long[][] c)
    {
        fpaddPRIME(a[0], b[0], c[0]);
        fpaddPRIME(a[1], b[1], c[1]);
    }

    // GF(p^2) subtraction, c = a-b in GF(p^2).
    protected void fp2sub(long[][] a, long[][] b, long[][] c)
    {
        fpsubPRIME(a[0], b[0], c[0]);
        fpsubPRIME(a[1], b[1], c[1]);
    }

    // GF(p^2) subtraction with correction with 4*p, c = a-b+4p in GF(p^2).
//    private void mp2_sub_p4(long[][] a, long[][] b, long[][] c)
//    {
//        mp_subPRIME_p4(a[0], b[0], c[0]);
//        mp_subPRIME_p4(a[1], b[1], c[1]);
//    }

    // Multiprecision multiplication, c = a*b mod p.
    protected void fpmul_mont(long[] ma, long[] mb, long[] mc)
    {
        long[] temp = new long[2*engine.params.NWORDS_FIELD];

        mp_mul(ma, mb, temp, engine.params.NWORDS_FIELD);
        rdc_mont(temp, mc);
    }

    // Multiprecision multiplication, c = a*b mod p.
    protected void fpmul_mont(long[] ma, int maOffset, long[] mb, long[] mc)
    {
        long[] temp = new long[2*engine.params.NWORDS_FIELD];

        mp_mul(ma, maOffset, mb, temp, engine.params.NWORDS_FIELD);
        rdc_mont(temp, mc);
    }

    // Chain to compute a^(p-3)/4 using Montgomery arithmetic.
    private void fpinv_chain_mont(long[] a)
    {
        int i, j;
        if (engine.params.NBITS_FIELD == 434)
        {
            long[] tt = new long[engine.params.NWORDS_FIELD];
            long[][] t = new long[31][engine.params.NWORDS_FIELD];

            // Precomputed table
            fpsqr_mont(a, tt);
            fpmul_mont(a, tt, t[0]);
            for (i = 0; i <= 29; i++) fpmul_mont(t[i], tt, t[i + 1]);

            fpcopy(a, 0, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[5], tt, tt);
            for (i = 0; i < 10; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[14], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[3], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[23], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[13], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[24], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[7], tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[12], tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[30], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[1], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[30], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[21], tt, tt);
            for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[2], tt, tt);
            for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[19], tt, tt);
            for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[1], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[24], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[26], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[16], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[10], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[6], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[0], tt, tt);
            for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[20], tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[9], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[25], tt, tt);
            for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[30], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[26], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(a, tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[28], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[6], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[10], tt, tt);
            for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[22], tt, tt);
            for (j = 0; j < 35; j++)
            {
                for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
                fpmul_mont(t[30], tt, tt);
            }
            fpcopy(tt, 0, a);
        }

        if (engine.params.NBITS_FIELD == 503)
        {
            long[][] t = new long[15][engine.params.NWORDS_FIELD];
            long[] tt = new long[engine.params.NWORDS_FIELD];

            // Precomputed table
            fpsqr_mont(a, tt);
            fpmul_mont(a, tt, t[0]);
            for (i = 0; i <= 13; i++) fpmul_mont(t[i], tt, t[i + 1]);

            fpcopy(a,0, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(a, tt, tt);
            for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[8], tt, tt);
            for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[6], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[9], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[0], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(a, tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[6], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[2], tt, tt);
            for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[8], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(a, tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[10], tt, tt);
            for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[0], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[10], tt, tt);
            for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[10], tt, tt);
            for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[5], tt, tt);
            for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[2], tt, tt);
            for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[6], tt, tt);
            for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[3], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[5], tt, tt);
            for (i = 0; i < 12; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[12], tt, tt);
            for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[8], tt, tt);
            for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[6], tt, tt);
            for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[12], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[11], tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[6], tt, tt);
            for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[5], tt, tt);
            for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[14], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[14], tt, tt);
            for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[5], tt, tt);
            for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[6], tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[8], tt, tt);
            for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
            fpmul_mont(a, tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[4], tt, tt);
            for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[6], tt, tt);
            for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[5], tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[7], tt, tt);
            for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
            fpmul_mont(a, tt, tt);
            for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[0], tt, tt);
            for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[11], tt, tt);
            for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[13], tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[1], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[10], tt, tt);
            for (j = 0; j < 49; j++)
            {
                for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
                fpmul_mont(t[14], tt, tt);
            }
            fpcopy(tt, 0, a);
        }

        if (engine.params.NBITS_FIELD == 610)
        {
            long[][] t = new long[31][engine.params.NWORDS_FIELD];
            long[] tt = new long[engine.params.NWORDS_FIELD];

            // Precomputed table
            fpsqr_mont(a, tt);
            fpmul_mont(a, tt, t[0]);
            for (i = 0; i <= 29; i++) fpmul_mont(t[i], tt, t[i + 1]);

            fpcopy(a, 0, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[6], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[30], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[25], tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[28], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[7], tt, tt);
            for (i = 0; i < 11; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[11], tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(a, tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[0], tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[3], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[16], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[24], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[28], tt, tt);
            for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[16], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[4], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[3], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[20], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[11], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[14], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[15], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[0], tt, tt);
            for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[15], tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[19], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[9], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[5], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[27], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[28], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[29], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[1], tt, tt);
            for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[3], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[2], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[30], tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[25], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[28], tt, tt);
            for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[22], tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[3], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[22], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[7], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[9], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[4], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[20], tt, tt);
            for (i = 0; i < 11; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[10], tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[26], tt, tt);
            for (i = 0; i < 11; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[2], tt, tt);
            for (j = 0; j < 50; j++)
            {
                for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
                fpmul_mont(t[30], tt, tt);
            }
            fpcopy(tt, 0, a);
        }

        if (engine.params.NBITS_FIELD == 751)
        {
            long[][] t = new long[27][engine.params.NWORDS_FIELD];
            long[] tt = new long[engine.params.NWORDS_FIELD];

            // Precomputed table
            fpsqr_mont(a, tt);
            fpmul_mont(a, tt, t[0]);
            fpmul_mont(t[0], tt, t[1]);
            fpmul_mont(t[1], tt, t[2]);
            fpmul_mont(t[2], tt, t[3]);
            fpmul_mont(t[3], tt, t[3]);
            for (i = 3; i <= 8; i++) fpmul_mont(t[i], tt, t[i + 1]);
            fpmul_mont(t[9], tt, t[9]);
            for (i = 9; i <= 20; i++) fpmul_mont(t[i], tt, t[i + 1]);
            fpmul_mont(t[21], tt, t[21]);
            for (i = 21; i <= 24; i++) fpmul_mont(t[i], tt, t[i + 1]);
            fpmul_mont(t[25], tt, t[25]);
            fpmul_mont(t[25], tt, t[26]);

            fpcopy(a, 0, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[20], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[24], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[11], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[8], tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[2], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[23], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[2], tt, tt);
            for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[2], tt, tt);
            for (i = 0; i < 10; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[15], tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[13], tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[26], tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[20], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[11], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[10], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[14], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[4], tt, tt);
            for (i = 0; i < 10; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[18], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[1], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[22], tt, tt);
            for (i = 0; i < 10; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[6], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[24], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[9], tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[18], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[17], tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(a, tt, tt);
            for (i = 0; i < 10; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[16], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[7], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[0], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[12], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[19], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[22], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[25], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[2], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[10], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[22], tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[18], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[4], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[14], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[13], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[5], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[23], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[21], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[2], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[23], tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[12], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[9], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[3], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[13], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[17], tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[26], tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[5], tt, tt);
            for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[8], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[2], tt, tt);
            for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[11], tt, tt);
            for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
            fpmul_mont(t[20], tt, tt);
            for (j = 0; j < 61; j++)
            {
                for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
                fpmul_mont(t[26], tt, tt);
            }
            fpcopy(tt,0, a);
        }
    }
}
