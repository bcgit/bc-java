package org.bouncycastle.pqc.crypto.sike;

import org.bouncycastle.util.Pack;

class Fpx
{
    private SIKEEngine engine;

    Fpx(SIKEEngine engine)
    {
        this.engine = engine;
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

    // Is x < y?
    private int is_digit_lessthan_ct(long x, long y)
    {
        return (int)((x ^ ((x ^ y) | ((x - y) ^ y))) >>> (Internal.RADIX - 1));
    }

    // Is x != 0?
    private int is_digit_nonzero_ct(long x)
    {
        return (int)((x | (0 - x)) >>> (Internal.RADIX - 1));
    }

    // Is x = 0?
    private int is_digit_zero_ct(long x)
    {
        return (1 ^ is_digit_nonzero_ct(x));
    }


    // GF(p^2) division by two, c = a/2  in GF(p^2).
    protected void fp2div2(long[][] a, long[][] c)
    {
        //todo/org : make fp class and change this to generic fpdiv2
        fpdiv2_PRIME(a[0], c[0]);
        fpdiv2_PRIME(a[1], c[1]);
    }

    // todo/org : move to fp_generic
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

    // todo/org : move to fp_generic
    // Multiprecision subtraction with correction with 2*p, c = a-b+2p.
    private void mp_subPRIME_p2(long[] a, long[] b, long[] c)
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

    // todo/org : move to fp_generic
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

    // todo/org : move to fp_generic
    // Digit multiplication, digit * digit -> 2-digit result
    private void digit_x_digit(long a, long b, long[] c)
    {
        long al, ah, bl, bh, temp;
        long albl, albh, ahbl, ahbh, res1, res2, res3, carry;
        long mask_low = ((long)(-1)) >>> (8 * 4), mask_high = ((long)(-1)) << (8 * 4);

        al = a & mask_low;  // Low part
        ah = a >>> (8 * 4); // High part
        bl = b & mask_low;
        bh = b >>> (8 * 4);

        albl = al * bl;
        albh = al * bh;
        ahbl = ah * bl;
        ahbh = ah * bh;
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

    // todo/org : move to fp_generic
    // Efficient Montgomery reduction using comba and exploiting the special form of the prime PRIME.
    // mc = ma*R^-1 mod PRIMEx2, where R = 2^448.
    // If ma < 2^448*PRIME, the output mc is in the range [0, 2*PRIME-1].
    // ma is assumed to be in Montgomery representation.
    private void rdc_mont(long[] ma, long[] mc)
    {
        int i, j, carry, count = engine.params.PRIME_ZERO_WORDS;
        long t = 0, u = 0, v = 0;
        long[] UV = new long[2];

        for (i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            mc[i] = 0;
        }

        for (i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            for (j = 0; j < i; j++)
            {
                if (j < (i - engine.params.PRIME_ZERO_WORDS + 1))
                {
                    //MUL
                    digit_x_digit(mc[j], engine.params.PRIMEp1[i - j], UV);

                    //ADDC
                    long tempReg = (UV[0]) + (0);
                    v = (v) + tempReg;
                    carry = (is_digit_lessthan_ct(tempReg, (0)) | is_digit_lessthan_ct((v), tempReg));

                    //ADDC
                    tempReg = (UV[1]) + (carry);
                    u = (u) + tempReg;
                    carry = (is_digit_lessthan_ct(tempReg, (carry)) | is_digit_lessthan_ct((u), tempReg));

                    t += carry;
                }
            }

            //ADDC
            long tempReg = (v) + (0);
            v = (ma[i]) + tempReg;
            carry = (is_digit_lessthan_ct(tempReg, (0)) | is_digit_lessthan_ct((v), tempReg));

            //ADDC
            tempReg = (u) + (carry);
            u = (0) + tempReg;
            carry = (is_digit_lessthan_ct(tempReg, (carry)) | is_digit_lessthan_ct((u), tempReg));

            t += carry;
            mc[i] = v;
            v = u;
            u = t;
            t = 0;
        }

        for (i = engine.params.NWORDS_FIELD; i < 2 * engine.params.NWORDS_FIELD - 1; i++)
        {
            if (count > 0)
            {
                count -= 1;
            }
            for (j = i - engine.params.NWORDS_FIELD + 1; j < engine.params.NWORDS_FIELD; j++)
            {
                if (j < (engine.params.NWORDS_FIELD - count))
                {
                    //MUL
                    digit_x_digit(mc[j], engine.params.PRIMEp1[i - j], UV);

                    //ADDC
                    long tempReg = (UV[0]) + (0);
                    v = (v) + tempReg;
                    carry = (is_digit_lessthan_ct(tempReg, (0)) | is_digit_lessthan_ct((v), tempReg));

                    //ADDC
                    tempReg = (UV[1]) + (carry);
                    u = (u) + tempReg;
                    carry = (is_digit_lessthan_ct(tempReg, (carry)) | is_digit_lessthan_ct((u), tempReg));

                    t += carry;
                }
            }

            //ADDC
            long tempReg = (v) + (0);
            v = (ma[i]) + tempReg;
            carry = (is_digit_lessthan_ct(tempReg, (0)) | is_digit_lessthan_ct((v), tempReg));

            //ADDC
            tempReg = (u) + (carry);
            u = (0) + tempReg;
            carry = (is_digit_lessthan_ct(tempReg, (carry)) | is_digit_lessthan_ct((u), tempReg));

            t += carry;
            mc[i - engine.params.NWORDS_FIELD] = v;
            v = u;
            u = t;
            t = 0;
        }

        //ADDC
        long tempReg = (v) + (0);
        v = (ma[2 * engine.params.NWORDS_FIELD - 1]) + tempReg;
        carry = (is_digit_lessthan_ct(tempReg, (0)) | is_digit_lessthan_ct((v), tempReg));

        mc[engine.params.NWORDS_FIELD - 1] = v;
    }

    // todo/org : move to fp_generic
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

    // todo/org : move to fp_generic
    // Modular addition, c = a+b mod PRIME.
    // Inputs: a, b in [0, 2*PRIME-1]
    // Output: c in [0, 2*PRIME-1]
    private void fpaddPRIME(long[] a, long[] b, long[] c)
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

    // todo/org : move to fp_generic
    // Modular subtraction, c = a-b mod PRIME.
    // Inputs: a, b in [0, 2*PRIME-1]
    // Output: c in [0, 2*PRIME-1]
    private void fpsubPRIME(long[] a, long[] b, long[] c)
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

    // todo/org : move to fp_generic
    // Modular negation, a = -a mod PRIME.
    // Input/output: a in [0, 2*PRIME-1]
    private void fpnegPRIME(long[] a)
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

    // todo/org : move to fp_generic
    // Conversion of a GF(p^2) element from Montgomery representation to standard representation,
    // c_i = ma_i*R^(-1) = a_i in GF(p^2).
    private void from_fp2mont(long[][] ma, long[][] c)
    {
        from_mont(ma[0], c[0]);
        from_mont(ma[1], c[1]);
    }

    // todo/org : move to fp_generic
    // Conversion of GF(p^2) element from Montgomery to standard representation, and encoding by removing leading 0 bytes
    protected void fp2_encode(long[][] x, byte[] enc, int encOffset)
    {
        long[][] t = new long[2][engine.params.NWORDS_FIELD];

        from_fp2mont(x, t);
        encode_to_bytes(t[0], enc, encOffset, engine.params.FP2_ENCODED_BYTES / 2);
        encode_to_bytes(t[1], enc, encOffset + engine.params.FP2_ENCODED_BYTES / 2, engine.params.FP2_ENCODED_BYTES / 2);
    }

    // Parse byte sequence back into GF(p^2) element, and conversion to Montgomery representation
    protected void fp2_decode(byte[] x, long[][] dec, int decOffset)
    {
        decode_to_digits(x, decOffset, dec[0], engine.params.FP2_ENCODED_BYTES / 2, engine.params.NWORDS_FIELD);
        decode_to_digits(x, decOffset + (engine.params.FP2_ENCODED_BYTES / 2), dec[1], engine.params.FP2_ENCODED_BYTES / 2, engine.params.NWORDS_FIELD);
        to_fp2mont(dec, dec);
    }

    // Conversion of a GF(p^2) element to Montgomery representation,
    // mc_i = a_i*R^2*R^(-1) = a_i*R in GF(p^2).
    private void to_fp2mont(long[][] a, long[][] mc)
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


    // todo/org : move to fp_generic
    // Modular correction to reduce field element a in [0, 2*PRIME-1] to [0, PRIME-1].
    private void fpcorrectionPRIME(long[] a)
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

    // Encoding digits to bytes according to endianness
    private void encode_to_bytes(long[] x, byte[] enc, int endOffset, int nbytes)
    {
        byte[] test = new byte[(nbytes + 7) & ~7];
        Pack.longToLittleEndian(x, test, 0);
        System.arraycopy(test, 0, enc, endOffset, nbytes);
    }

    // Decoding bytes to digits according to endianness
    protected void decode_to_digits(byte[] x, int xOffset, long[] dec, int nbytes, int ndigits)
    {
        // x -> dec
        dec[ndigits - 1] = 0;
        byte[] temp = new byte[(nbytes + 7) & ~7];
        System.arraycopy(x, xOffset, temp, 0, nbytes);
        Pack.littleEndianToLong(temp, 0, dec);

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

        for (i = 0; i < engine.params.NWORDS_FIELD - 1; i++)
        {
            //SHIFTR
            x[i] = (x[i] >>> 1) ^ (x[i + 1] << (Internal.RADIX - 1));
        }
        x[engine.params.NWORDS_FIELD - 1] >>>= 1;
    }

    // Copy a GF(p^2) element, c = a.
    protected void fp2copy(long[][] a, long[][] c)
    {
        fpcopy(a[0], 0, c[0]);
        fpcopy(a[1], 0, c[1]);
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
        long t = 0, u = 0, v = 0;
        long[] UV = new long[2];
        int carry = 0;

        for (i = 0; i < nwords; i++)
        {
            for (j = 0; j <= i; j++)
            {
                //MUL
                digit_x_digit(a[j], b[i - j], UV);

                //ADDC
                long tempReg = UV[0] + 0;
                v = v + tempReg;
                carry = (is_digit_lessthan_ct(tempReg, 0) | is_digit_lessthan_ct(v, tempReg));

                //ADDC
                tempReg = UV[1] + carry;
                u = u + tempReg;
                carry = (is_digit_lessthan_ct(tempReg, carry) | is_digit_lessthan_ct(u, tempReg));

                t += carry;
            }
            c[i] = v;
            v = u;
            u = t;
            t = 0;
        }

        for (i = nwords; i < 2 * nwords - 1; i++)
        {
            for (j = i - nwords + 1; j < nwords; j++)
            {
                //MUL
                digit_x_digit(a[j], b[i - j], UV);

                //ADDC
                long tempReg = UV[0] + 0;
                v = v + tempReg;
                carry = (is_digit_lessthan_ct(tempReg, 0) | is_digit_lessthan_ct(v, tempReg));

                //ADDC
                tempReg = UV[1] + carry;
                u = u + tempReg;
                carry = (is_digit_lessthan_ct(tempReg, carry) | is_digit_lessthan_ct(u, tempReg));

                t += carry;
            }
            c[i] = v;
            v = u;
            u = t;
            t = 0;
        }
        c[2 * nwords - 1] = v;
    }

    // GF(p^2) multiplication using Montgomery arithmetic, c = a*b in GF(p^2).
    // Inputs: a = a0+a1*i and b = b0+b1*i, where a0, a1, b0, b1 are in [0, 2*p-1]
    // Output: c = c0+c1*i, where c0, c1 are in [0, 2*p-1]
    protected void fp2mul_mont(long[][] a, long[][] b, long[][] c)
    {
        long[] t1 = new long[engine.params.NWORDS_FIELD],
            t2 = new long[engine.params.NWORDS_FIELD];
        long[] tt1 = new long[2 * engine.params.NWORDS_FIELD],
            tt2 = new long[2 * engine.params.NWORDS_FIELD],
            tt3 = new long[2 * engine.params.NWORDS_FIELD];

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
        long[] t1 = new long[engine.params.NWORDS_FIELD],
            t2 = new long[engine.params.NWORDS_FIELD];
        long[] tt1 = new long[2 * engine.params.NWORDS_FIELD],
            tt2 = new long[2 * engine.params.NWORDS_FIELD],
            tt3 = new long[2 * engine.params.NWORDS_FIELD];

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

    // Multiprecision subtraction, c = c-a-b, where lng(a) = lng(b) = 2*engine.params.NWORDS_FIELD.
    private void mp_dblsubfast(long[] a, long[] b, long[] c)
    {
        mp_sub(c, a, c, 2 * engine.params.NWORDS_FIELD);
        mp_sub(c, b, c, 2 * engine.params.NWORDS_FIELD);
    }

    // Multiprecision subtraction, c = a-b, where lng(a) = lng(b) = nwords. Returns the borrow bit.
    private int mp_sub(long[] a, long[] b, long[] c, int nwords)
    {
        int i, borrow = 0;

        for (i = 0; i < nwords; i++)
        {
            //SUBC
            long tempReg = a[i] - b[i];
            int borrowReg = (is_digit_lessthan_ct(a[i], b[i]) | (borrow & is_digit_zero_ct(tempReg)));
            c[i] = tempReg - (long)(borrow);
            borrow = borrowReg;
        }
        return borrow;
    }

    // Multiprecision subtraction followed by addition with p*2^MAXBITS_FIELD, c = a-b+(p*2^MAXBITS_FIELD) if a-b < 0, otherwise c=a-b. 
    private void mp_subaddfast(long[] a, long[] b, long[] c)
    {
        long[] t1 = new long[engine.params.NWORDS_FIELD];

        long mask = 0 - (long)mp_sub(a, b, c, 2 * engine.params.NWORDS_FIELD);
        for (int i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            t1[i] = engine.params.PRIME[i] & mask; // todo replace with PRIME
        }
        mp_add(c, engine.params.NWORDS_FIELD, t1, c, engine.params.NWORDS_FIELD, engine.params.NWORDS_FIELD);
    }

    // Multiprecision squaring, c = a^2 mod p.
    protected void fpsqr_mont(long[] ma, long[] mc)
    {
        long[] temp = new long[2 * engine.params.NWORDS_FIELD];

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

    // GF(p^2) addition, c = a+b in GF(p^2).
    protected void fp2add(long[][] a, long[][] b, long[][] c)
    {
        //todo/org : make fp class and change this to generic function
        fpaddPRIME(a[0], b[0], c[0]);
        fpaddPRIME(a[1], b[1], c[1]);
    }

    // GF(p^2) subtraction, c = a-b in GF(p^2).
    protected void fp2sub(long[][] a, long[][] b, long[][] c)
    {
        //todo/org : make fp class and change this to generic function
        fpsubPRIME(a[0], b[0], c[0]);
        fpsubPRIME(a[1], b[1], c[1]);
    }

    // GF(p^2) subtraction with correction with 4*p, c = a-b+4p in GF(p^2).
    private void mp2_sub_p4(long[][] a, long[][] b, long[][] c)
    {
        //todo/org : make fp class and change this to generic function
        mp_subPRIME_p4(a[0], b[0], c[0]);
        mp_subPRIME_p4(a[1], b[1], c[1]);
    }

    // Multiprecision multiplication, c = a*b mod p.
    private void fpmul_mont(long[] ma, long[] mb, long[] mc)
    {
        long[] temp = new long[2 * engine.params.NWORDS_FIELD];

        mp_mul(ma, mb, temp, engine.params.NWORDS_FIELD);
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
            for (i = 0; i <= 29; i++)
            {
                fpmul_mont(t[i], tt, t[i + 1]);
            }

            fpcopy(a, 0, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[5], tt, tt);
            for (i = 0; i < 10; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[14], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[3], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[23], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[13], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[24], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[7], tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[12], tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[30], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[1], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[30], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[21], tt, tt);
            for (i = 0; i < 9; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[2], tt, tt);
            for (i = 0; i < 9; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[19], tt, tt);
            for (i = 0; i < 9; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[1], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[24], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[26], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[16], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[10], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[6], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[0], tt, tt);
            for (i = 0; i < 9; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[20], tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[9], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[25], tt, tt);
            for (i = 0; i < 9; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[30], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[26], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(a, tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[28], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[6], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[10], tt, tt);
            for (i = 0; i < 9; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[22], tt, tt);
            for (j = 0; j < 35; j++)
            {
                for (i = 0; i < 6; i++)
                {
                    fpsqr_mont(tt, tt);
                }
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
            for (i = 0; i <= 13; i++)
            {
                fpmul_mont(t[i], tt, t[i + 1]);
            }

            fpcopy(a, 0, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(a, tt, tt);
            for (i = 0; i < 5; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[8], tt, tt);
            for (i = 0; i < 5; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[6], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[9], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[0], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(a, tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[6], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[2], tt, tt);
            for (i = 0; i < 5; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[8], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(a, tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[10], tt, tt);
            for (i = 0; i < 5; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[0], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[10], tt, tt);
            for (i = 0; i < 5; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[10], tt, tt);
            for (i = 0; i < 5; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[5], tt, tt);
            for (i = 0; i < 5; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[2], tt, tt);
            for (i = 0; i < 5; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[6], tt, tt);
            for (i = 0; i < 5; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[3], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[5], tt, tt);
            for (i = 0; i < 12; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[12], tt, tt);
            for (i = 0; i < 5; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[8], tt, tt);
            for (i = 0; i < 5; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[6], tt, tt);
            for (i = 0; i < 5; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[12], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[11], tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[6], tt, tt);
            for (i = 0; i < 5; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[5], tt, tt);
            for (i = 0; i < 5; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[14], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[14], tt, tt);
            for (i = 0; i < 5; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[5], tt, tt);
            for (i = 0; i < 5; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[6], tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[8], tt, tt);
            for (i = 0; i < 5; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(a, tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[4], tt, tt);
            for (i = 0; i < 5; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[6], tt, tt);
            for (i = 0; i < 5; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[5], tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[7], tt, tt);
            for (i = 0; i < 5; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(a, tt, tt);
            for (i = 0; i < 5; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[0], tt, tt);
            for (i = 0; i < 5; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[11], tt, tt);
            for (i = 0; i < 5; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[13], tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[1], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[10], tt, tt);
            for (j = 0; j < 49; j++)
            {
                for (i = 0; i < 5; i++)
                {
                    fpsqr_mont(tt, tt);
                }
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
            for (i = 0; i <= 29; i++)
            {
                fpmul_mont(t[i], tt, t[i + 1]);
            }

            fpcopy(a, 0, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[6], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[30], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[25], tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[28], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[7], tt, tt);
            for (i = 0; i < 11; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[11], tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(a, tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[0], tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[3], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[16], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[24], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[28], tt, tt);
            for (i = 0; i < 9; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[16], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[4], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[3], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[20], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[11], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[14], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[15], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[0], tt, tt);
            for (i = 0; i < 9; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[15], tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[19], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[9], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[5], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[27], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[28], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[29], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[1], tt, tt);
            for (i = 0; i < 9; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[3], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[2], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[30], tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[25], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[28], tt, tt);
            for (i = 0; i < 9; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[22], tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[3], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[22], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[7], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[9], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[4], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[20], tt, tt);
            for (i = 0; i < 11; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[10], tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[26], tt, tt);
            for (i = 0; i < 11; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[2], tt, tt);
            for (j = 0; j < 50; j++)
            {
                for (i = 0; i < 6; i++)
                {
                    fpsqr_mont(tt, tt);
                }
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
            for (i = 3; i <= 8; i++)
            {
                fpmul_mont(t[i], tt, t[i + 1]);
            }
            fpmul_mont(t[9], tt, t[9]);
            for (i = 9; i <= 20; i++)
            {
                fpmul_mont(t[i], tt, t[i + 1]);
            }
            fpmul_mont(t[21], tt, t[21]);
            for (i = 21; i <= 24; i++)
            {
                fpmul_mont(t[i], tt, t[i + 1]);
            }
            fpmul_mont(t[25], tt, t[25]);
            fpmul_mont(t[25], tt, t[26]);

            fpcopy(a, 0, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[20], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[24], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[11], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[8], tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[2], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[23], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[2], tt, tt);
            for (i = 0; i < 9; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[2], tt, tt);
            for (i = 0; i < 10; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[15], tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[13], tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[26], tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[20], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[11], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[10], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[14], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[4], tt, tt);
            for (i = 0; i < 10; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[18], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[1], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[22], tt, tt);
            for (i = 0; i < 10; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[6], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[24], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[9], tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[18], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[17], tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(a, tt, tt);
            for (i = 0; i < 10; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[16], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[7], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[0], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[12], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[19], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[22], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[25], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[2], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[10], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[22], tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[18], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[4], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[14], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[13], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[5], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[23], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[21], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[2], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[23], tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[12], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[9], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[3], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[13], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[17], tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[26], tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[5], tt, tt);
            for (i = 0; i < 8; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[8], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[2], tt, tt);
            for (i = 0; i < 6; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[11], tt, tt);
            for (i = 0; i < 7; i++)
            {
                fpsqr_mont(tt, tt);
            }
            fpmul_mont(t[20], tt, tt);
            for (j = 0; j < 61; j++)
            {
                for (i = 0; i < 6; i++)
                {
                    fpsqr_mont(tt, tt);
                }
                fpmul_mont(t[26], tt, tt);
            }
            fpcopy(tt, 0, a);
        }
    }
}
