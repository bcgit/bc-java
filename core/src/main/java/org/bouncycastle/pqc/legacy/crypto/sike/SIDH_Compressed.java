package org.bouncycastle.pqc.legacy.crypto.sike;

import java.security.SecureRandom;

import org.bouncycastle.util.Arrays;

class SIDH_Compressed
{
    private SIKEEngine engine;

    public SIDH_Compressed(SIKEEngine engine)
    {
        this.engine = engine;
    }

    protected void init_basis(long[] gen, long[][] XP, long[][] XQ, long[][] XR)
    { // Initialization of basis points

        engine.fpx.fpcopy(gen, 0, XP[0]);
        engine.fpx.fpcopy(gen, engine.params.NWORDS_FIELD, XP[1]);
        engine.fpx.fpcopy(gen, 2 * engine.params.NWORDS_FIELD, XQ[0]);
        engine.fpx.fpcopy(gen, 3 * engine.params.NWORDS_FIELD, XQ[1]);
        engine.fpx.fpcopy(gen, 4 * engine.params.NWORDS_FIELD, XR[0]);
        engine.fpx.fpcopy(gen, 5 * engine.params.NWORDS_FIELD, XR[1]);
    }


    protected void FormatPrivKey_B(byte[] skB)
    {
        skB[engine.params.SECRETKEY_B_BYTES - 2] &= engine.params.MASK3_BOB;
        skB[engine.params.SECRETKEY_B_BYTES - 1] &= engine.params.MASK2_BOB;    // Clear necessary bits so that 3*ephemeralsk is still less than Bob_order
        engine.fpx.mul3(skB);       // Multiply ephemeralsk by 3
    }

    // Generation of Alice's secret key
    // Outputs random value in [0, 2^eA - 1]
    protected void random_mod_order_A(byte[] random_digits, SecureRandom random)
    {
        byte[] temp = new byte[engine.params.SECRETKEY_A_BYTES];
        random.nextBytes(temp);
        System.arraycopy(temp, 0, random_digits, 0, engine.params.SECRETKEY_A_BYTES);
        random_digits[0] &= 0xFE;                            // Make private scalar even
        random_digits[engine.params.SECRETKEY_A_BYTES - 1] &= engine.params.MASK_ALICE;    // Masking last byte
    }

    // Generation of Bob's secret key
    // Outputs random value in [0, 2^Floor(Log(2, oB)) - 1]
    protected void random_mod_order_B(byte[] random_digits, SecureRandom random)
    {
        byte[] temp = new byte[engine.params.SECRETKEY_B_BYTES];
        random.nextBytes(temp);
        System.arraycopy(temp, 0, random_digits, 0, engine.params.SECRETKEY_A_BYTES);
        FormatPrivKey_B(random_digits);
    }

    // Project 3-point ladder
    protected void Ladder3pt_dual(PointProj[] Rs, long[] m, int AliceOrBob, PointProj R, long[][] A24)
    {
        PointProj R0 = new PointProj(engine.params.NWORDS_FIELD),
            R2 = new PointProj(engine.params.NWORDS_FIELD);
        long mask;
        int i, nbits, bit, swap, prevbit = 0;

        if (AliceOrBob == engine.params.ALICE)
        {
            nbits = engine.params.OALICE_BITS;
        }
        else
        {
            nbits = engine.params.OBOB_BITS;
        }

        engine.fpx.fp2copy(Rs[1].X, R0.X);
        engine.fpx.fp2copy(Rs[1].Z, R0.Z);
        engine.fpx.fp2copy(Rs[2].X, R2.X);
        engine.fpx.fp2copy(Rs[2].Z, R2.Z);
        engine.fpx.fp2copy(Rs[0].X, R.X);
        engine.fpx.fp2copy(Rs[0].Z, R.Z);

        // Main loop
        for (i = 0; i < nbits; i++)
        {
            bit = (int)((m[i >>> Internal.LOG2RADIX] >>> (i & (Internal.RADIX - 1))) & 1);
            swap = bit ^ prevbit;
            prevbit = bit;
            mask = 0 - (long)swap;

            engine.isogeny.swap_points(R, R2, mask);
            engine.isogeny.xDBLADD(R0, R2, R.X, A24);
            engine.fpx.fp2mul_mont(R2.X, R.Z, R2.X);
        }
        swap = 0 ^ prevbit;
        mask = 0 - (long)swap;
        engine.isogeny.swap_points(R, R2, mask);
    }


    protected void Elligator2(long[][] a24, int[] r, int rIndex, long[][] x, byte[] bit, int bitOffset, int COMPorDEC)
    { // Generate an x-coordinate of a point on curve with (affine) coefficient a24 
        // Use the counter r
        int i;
        long[] one_fp = new long[engine.params.NWORDS_FIELD],
            a2 = new long[engine.params.NWORDS_FIELD],
            b2 = new long[engine.params.NWORDS_FIELD],
            N = new long[engine.params.NWORDS_FIELD],
            temp0 = new long[engine.params.NWORDS_FIELD],
            temp1 = new long[engine.params.NWORDS_FIELD];
        long[][] A = new long[2][engine.params.NWORDS_FIELD],
            y2 = new long[2][engine.params.NWORDS_FIELD];

        int t_ptr = 0;
        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, one_fp);
        engine.fpx.fp2add(a24, a24, A);
        engine.fpx.fpsubPRIME(A[0], one_fp, A[0]);
        engine.fpx.fp2add(A, A, A);                       // A = 4*a24-2

        // Elligator computation
        t_ptr = r[rIndex]; //(long[][] *)&v_3_torsion[r];
        engine.fpx.fp2mul_mont(A, engine.params.v_3_torsion[t_ptr], x);     // x = A*v; v := 1/(1 + U*r^2) table lookup
        engine.fpx.fp2neg(x);                             // x = -A*v;

        if (COMPorDEC == 0) //COMPRESSION
        {
            engine.fpx.fp2add(A, x, y2);                      // y2 = x + A
            engine.fpx.fp2mul_mont(y2, x, y2);              // y2 = x*(x + A)
            engine.fpx.fpaddPRIME(y2[0], one_fp, y2[0]);         // y2 = x(x + A) + 1
            engine.fpx.fp2mul_mont(x, y2, y2);                // y2 = x*(x^2 + Ax + 1);
            engine.fpx.fpsqr_mont(y2[0], a2);
            engine.fpx.fpsqr_mont(y2[1], b2);
            engine.fpx.fpaddPRIME(a2, b2, N);                      // N := norm(y2);
            engine.fpx.fpcopy(N, 0, temp0);
            for (i = 0; i < engine.params.OALICE_BITS - 2; i++)
            {
                engine.fpx.fpsqr_mont(temp0, temp0);
            }
            for (i = 0; i < engine.params.OBOB_EXPON; i++)
            {
                engine.fpx.fpsqr_mont(temp0, temp1);
                engine.fpx.fpmul_mont(temp0, temp1, temp0);
            }
            engine.fpx.fpsqr_mont(temp0, temp1);              // z = N^((p + 1) div 4);
            engine.fpx.fpcorrectionPRIME(temp1);
            engine.fpx.fpcorrectionPRIME(N);
            if (!Fpx.subarrayEquals(temp1, N, engine.params.NWORDS_FIELD))
            {
                engine.fpx.fp2neg(x);
                engine.fpx.fp2sub(x, A, x);     // x = -x - A;
                if (COMPorDEC == 0)
                {
                    bit[bitOffset] = 1;
                }
            }
        }
        else
        {
            if (bit[bitOffset] == 1)
            {
                engine.fpx.fp2neg(x);
                engine.fpx.fp2sub(x, A, x);       // x = -x - A;
            }
        }
    }


    protected void make_positive(long[][] x)
    {
        int nbytes = engine.params.NWORDS_FIELD;
        long[] zero = new long[engine.params.NWORDS_FIELD];

        engine.fpx.from_fp2mont(x, x);
        if (!Fpx.subarrayEquals(x[0], zero, nbytes))
        {
            if ((x[0][0] & 1) == 1)
            {
                engine.fpx.fp2neg(x);
            }
        }
        else
        {
            if ((x[1][0] & 1) == 1)
            {
                engine.fpx.fp2neg(x);
            }
        }
        engine.fpx.to_fp2mont(x, x);
    }


    protected void BiQuad_affine(long[][] a24, long[][] x0, long[][] x1, PointProj R)
    {
        long[][] Ap2 = new long[2][engine.params.NWORDS_FIELD],
            aa = new long[2][engine.params.NWORDS_FIELD],
            bb = new long[2][engine.params.NWORDS_FIELD],
            cc = new long[2][engine.params.NWORDS_FIELD],
            t0 = new long[2][engine.params.NWORDS_FIELD],
            t1 = new long[2][engine.params.NWORDS_FIELD];

        engine.fpx.fp2add(a24, a24, Ap2);
        engine.fpx.fp2add(Ap2, Ap2, Ap2);    // Ap2 = a+2 = 4*a24

        engine.fpx.fp2sub(x0, x1, aa);
        engine.fpx.fp2sqr_mont(aa, aa);

        engine.fpx.fp2mul_mont(x0, x1, cc);
        engine.fpx.fpsubPRIME(cc[0], engine.params.Montgomery_one, cc[0]);
        engine.fpx.fp2sqr_mont(cc, cc);

        engine.fpx.fpsubPRIME(x0[0], engine.params.Montgomery_one, bb[0]);
        engine.fpx.fpcopy(x0[1], 0, bb[1]);
        engine.fpx.fp2sqr_mont(bb, bb);
        engine.fpx.fp2mul_mont(Ap2, x0, t0);
        engine.fpx.fp2add(bb, t0, bb);
        engine.fpx.fp2mul_mont(x1, bb, bb);
        engine.fpx.fpsubPRIME(x1[0], engine.params.Montgomery_one, t0[0]);
        engine.fpx.fpcopy(x1[1], 0, t0[1]);
        engine.fpx.fp2sqr_mont(t0, t0);
        engine.fpx.fp2mul_mont(Ap2, x1, t1);
        engine.fpx.fp2add(t0, t1, t0);
        engine.fpx.fp2mul_mont(x0, t0, t0);
        engine.fpx.fp2add(bb, t0, bb);
        engine.fpx.fp2add(bb, bb, bb);

        engine.fpx.fp2sqr_mont(bb, t0);
        engine.fpx.fp2mul_mont(aa, cc, t1);
        engine.fpx.fp2add(t1, t1, t1);
        engine.fpx.fp2add(t1, t1, t1);
        engine.fpx.fp2sub(t0, t1, t0);
        engine.fpx.sqrt_Fp2(t0, t0);
        make_positive(t0);    // Make the sqrt "positive"
        engine.fpx.fp2add(bb, t0, R.X);
        engine.fpx.fp2add(aa, aa, R.Z);
    }


    protected void get_4_isog_dual(PointProj P, long[][] A24, long[][] C24, long[][][] coeff)
    {
        engine.fpx.fp2sub(P.X, P.Z, coeff[1]);
        engine.fpx.fp2add(P.X, P.Z, coeff[2]);
        engine.fpx.fp2sqr_mont(P.Z, coeff[4]);
        engine.fpx.fp2add(coeff[4], coeff[4], coeff[0]);
        engine.fpx.fp2sqr_mont(coeff[0], C24);
        engine.fpx.fp2add(coeff[0], coeff[0], coeff[0]);
        engine.fpx.fp2sqr_mont(P.X, coeff[3]);
        engine.fpx.fp2add(coeff[3], coeff[3], A24);
        engine.fpx.fp2sqr_mont(A24, A24);
    }

    protected void eval_dual_2_isog(long[][] X2, long[][] Z2, PointProj P)
    {
        long[][] t0 = new long[2][engine.params.NWORDS_FIELD];

        engine.fpx.fp2add(P.X, P.Z, t0);
        engine.fpx.fp2sub(P.X, P.Z, P.Z);
        engine.fpx.fp2sqr_mont(t0, t0);
        engine.fpx.fp2sqr_mont(P.Z, P.Z);
        engine.fpx.fp2sub(t0, P.Z, P.Z);
        engine.fpx.fp2mul_mont(X2, P.Z, P.Z);
        engine.fpx.fp2mul_mont(Z2, t0, P.X);
    }

    protected void eval_final_dual_2_isog(PointProj P)
    {
        long[][] t0 = new long[2][engine.params.NWORDS_FIELD],
            t1 = new long[2][engine.params.NWORDS_FIELD];
        long[] t2 = new long[engine.params.NWORDS_FIELD];

        engine.fpx.fp2add(P.X, P.Z, t0);
        engine.fpx.fp2mul_mont(P.X, P.Z, t1);
        engine.fpx.fp2sqr_mont(t0, P.X);
        engine.fpx.fpcopy(P.X[0], 0, t2);
        engine.fpx.fpcopy(P.X[1], 0, (P.X)[0]);
        engine.fpx.fpcopy(t2, 0, P.X[1]);
        engine.fpx.fpnegPRIME((P.X)[1]);
        engine.fpx.fp2add(t1, t1, P.Z);
        engine.fpx.fp2add(P.Z, P.Z, P.Z);
    }


    protected void eval_dual_4_isog_shared(long[][] X4pZ4, long[][] X42, long[][] Z42, long[][][] coeff, int coeffOffset)
    {
        engine.fpx.fp2sub(X42, Z42, coeff[0 + coeffOffset]);
        engine.fpx.fp2add(X42, Z42, coeff[1 + coeffOffset]);
        engine.fpx.fp2sqr_mont(X4pZ4, coeff[2 + coeffOffset]);
        engine.fpx.fp2sub(coeff[2 + coeffOffset], coeff[1 + coeffOffset], coeff[2 + coeffOffset]);
    }


    protected void eval_dual_4_isog(long[][] A24, long[][] C24, long[][][] coeff, int coeffOffset, PointProj P)
    {
        long[][] t0 = new long[2][engine.params.NWORDS_FIELD],
            t1 = new long[2][engine.params.NWORDS_FIELD],
            t2 = new long[2][engine.params.NWORDS_FIELD],
            t3 = new long[2][engine.params.NWORDS_FIELD];

        engine.fpx.fp2add(P.X, P.Z, t0);
        engine.fpx.fp2sub(P.X, P.Z, t1);
        engine.fpx.fp2sqr_mont(t0, t0);
        engine.fpx.fp2sqr_mont(t1, t1);
        engine.fpx.fp2sub(t0, t1, t2);
        engine.fpx.fp2sub(C24, A24, t3);
        engine.fpx.fp2mul_mont(t2, t3, t3);
        engine.fpx.fp2mul_mont(C24, t0, t2);
        engine.fpx.fp2sub(t2, t3, t2);
        engine.fpx.fp2mul_mont(t2, t0, P.X);
        engine.fpx.fp2mul_mont(t3, t1, P.Z);
        engine.fpx.fp2mul_mont(coeff[0 + coeffOffset], P.X, P.X);
        engine.fpx.fp2mul_mont(coeff[1 + coeffOffset], P.Z, t0);
        engine.fpx.fp2add(P.X, t0, P.X);
        engine.fpx.fp2mul_mont(coeff[2 + coeffOffset], P.Z, P.Z);
    }


    protected void eval_full_dual_4_isog(long[][][][] As, PointProj P)
    {
        for (int i = 0; i < engine.params.MAX_Alice; i++)
        {
            eval_dual_4_isog(As[engine.params.MAX_Alice - i][0],
                As[engine.params.MAX_Alice - i][1],
                As[engine.params.MAX_Alice - i - 1], 2,
                P);
        }
        if (engine.params.OALICE_BITS % 2 == 1)
        {
            eval_dual_2_isog(As[engine.params.MAX_Alice][2], As[engine.params.MAX_Alice][3], P);
        }
        eval_final_dual_2_isog(P);    // to A = 0
    }


    protected void TripleAndParabola_proj(PointProjFull R, long[][] l1x, long[][] l1z)
    {
        engine.fpx.fp2sqr_mont(R.X, l1z);
        engine.fpx.fp2add(l1z, l1z, l1x);
        engine.fpx.fp2add(l1x, l1z, l1x);
        engine.fpx.fpaddPRIME(l1x[0], engine.params.Montgomery_one, l1x[0]);
        engine.fpx.fp2add(R.Y, R.Y, l1z);
    }


    protected void Tate3_proj(PointProjFull P, PointProjFull Q, long[][] gX, long[][] gZ)
    {
        long[][] t0 = new long[2][engine.params.NWORDS_FIELD],
            l1x = new long[2][engine.params.NWORDS_FIELD];

        TripleAndParabola_proj(P, l1x, gZ);
        engine.fpx.fp2sub(Q.X, P.X, gX);
        engine.fpx.fp2mul_mont(l1x, gX, gX);
        engine.fpx.fp2sub(P.Y, Q.Y, t0);
        engine.fpx.fp2mul_mont(gZ, t0, t0);
        engine.fpx.fp2add(gX, t0, gX);
    }


    protected void FinalExpo3(long[][] gX, long[][] gZ)
    {
        int i;
        long[][] f_ = new long[2][engine.params.NWORDS_FIELD];

        engine.fpx.fp2copy(gZ, f_);
        engine.fpx.fpnegPRIME(f_[1]);
        engine.fpx.fp2mul_mont(gX, f_, f_);
        engine.fpx.fp2inv_mont_bingcd(f_);
        engine.fpx.fpnegPRIME(gX[1]);
        engine.fpx.fp2mul_mont(gX, gZ, gX);
        engine.fpx.fp2mul_mont(gX, f_, gX);
        for (i = 0; i < engine.params.OALICE_BITS; i++)
        {
            engine.fpx.fp2sqr_mont(gX, gX);
        }
        for (i = 0; i < engine.params.OBOB_EXPON - 1; i++)
        {
            engine.fpx.cube_Fp2_cycl(gX, engine.params.Montgomery_one);
        }
    }


    protected void FinalExpo3_2way(long[][][] gX, long[][][] gZ)
    {
        int i, j;
        long[][][] f_ = new long[2][2][engine.params.NWORDS_FIELD],
            finv = new long[2][2][engine.params.NWORDS_FIELD];

        for (i = 0; i < 2; i++)
        {
            engine.fpx.fp2copy(gZ[i], f_[i]);
            engine.fpx.fpnegPRIME(f_[i][1]);    // Conjugate
            engine.fpx.fp2mul_mont(gX[i], f_[i], f_[i]);
        }
        engine.fpx.mont_n_way_inv(f_, 2, finv);
        for (i = 0; i < 2; i++)
        {
            engine.fpx.fpnegPRIME(gX[i][1]);
            engine.fpx.fp2mul_mont(gX[i], gZ[i], gX[i]);
            engine.fpx.fp2mul_mont(gX[i], finv[i], gX[i]);
            for (j = 0; j < engine.params.OALICE_BITS; j++)
            {
                engine.fpx.fp2sqr_mont(gX[i], gX[i]);
            }
            for (j = 0; j < engine.params.OBOB_EXPON - 1; j++)
            {
                engine.fpx.cube_Fp2_cycl(gX[i], engine.params.Montgomery_one);
            }
        }
    }


    private boolean FirstPoint_dual(PointProj P, PointProjFull R, byte[] ind)
    {
        PointProjFull R3 = new PointProjFull(engine.params.NWORDS_FIELD),
            S3 = new PointProjFull(engine.params.NWORDS_FIELD);
        long[][][] gX = new long[2][2][engine.params.NWORDS_FIELD],
            gZ = new long[2][2][engine.params.NWORDS_FIELD];
        long[] zero = new long[engine.params.NWORDS_FIELD];
        int nbytes = engine.params.NWORDS_FIELD;
        int alpha, beta;

        engine.fpx.fpcopy(engine.params.B_gen_3_tors, 0 * engine.params.NWORDS_FIELD, (R3.X)[0]);
        engine.fpx.fpcopy(engine.params.B_gen_3_tors, 1 * engine.params.NWORDS_FIELD, (R3.X)[1]);
        engine.fpx.fpcopy(engine.params.B_gen_3_tors, 2 * engine.params.NWORDS_FIELD, (R3.Y)[0]);
        engine.fpx.fpcopy(engine.params.B_gen_3_tors, 3 * engine.params.NWORDS_FIELD, (R3.Y)[1]);
        engine.fpx.fpcopy(engine.params.B_gen_3_tors, 4 * engine.params.NWORDS_FIELD, (S3.X)[0]);
        engine.fpx.fpcopy(engine.params.B_gen_3_tors, 5 * engine.params.NWORDS_FIELD, (S3.X)[1]);
        engine.fpx.fpcopy(engine.params.B_gen_3_tors, 6 * engine.params.NWORDS_FIELD, (S3.Y)[0]);
        engine.fpx.fpcopy(engine.params.B_gen_3_tors, 7 * engine.params.NWORDS_FIELD, (S3.Y)[1]);

        engine.isogeny.CompletePoint(P, R);

        Tate3_proj(R3, R, gX[0], gZ[0]);
        Tate3_proj(S3, R, gX[1], gZ[1]);
        FinalExpo3_2way(gX, gZ);

        // Do small DLog with respect to g_R3_S3
        engine.fpx.fp2correction(gX[0]);
        engine.fpx.fp2correction(gX[1]);

        if (Fpx.subarrayEquals(gX[0][1], zero, nbytes)) // = 1
        {
            alpha = 0;
        }
        else if (Fpx.subarrayEquals(gX[0][1], engine.params.g_R_S_im, nbytes)) // = g_R3_S3
        {
            alpha = 1;
        }
        else    // = g_R3_S3^2
        {
            alpha = 2;
        }

        if (Fpx.subarrayEquals(gX[1][1], zero, nbytes)) // = 1
        {
            beta = 0;
        }
        else if (Fpx.subarrayEquals(gX[1][1], engine.params.g_R_S_im, nbytes))// = g_R3_S3
        {
            beta = 1;
        }
        else    // = g_R3_S3^2
        {
            beta = 2;
        }

        if (alpha == 0 && beta == 0)   // Not full order
        {
            return false;
        }

        // Return the 3-torsion point that R lies above
        if (alpha == 0)         // Lies above R3
        {
            ind[0] = 0;
        }
        else if (beta == 0)         // Lies above S3
        {
            ind[0] = 1;
        }
        else if (alpha + beta == 3) // Lies above R3+S3
        {
            ind[0] = 3;
        }
        else                        // Lies above R3-S3
        {
            ind[0] = 2;
        }

        return true;
    }


    private boolean SecondPoint_dual(PointProj P, PointProjFull R, byte[] ind)
    {
        PointProjFull RS3 = new PointProjFull(engine.params.NWORDS_FIELD);
        long[][] gX = new long[2][engine.params.NWORDS_FIELD],
            gZ = new long[2][engine.params.NWORDS_FIELD];

        long[] zero = new long[engine.params.NWORDS_FIELD];
        int nbytes = engine.params.NWORDS_FIELD;

        // Pair with 3-torsion point determined by first point
        engine.fpx.fpcopy(engine.params.B_gen_3_tors, (4 * ind[0] + 0) * engine.params.NWORDS_FIELD, (RS3.X)[0]);
        engine.fpx.fpcopy(engine.params.B_gen_3_tors, (4 * ind[0] + 1) * engine.params.NWORDS_FIELD, (RS3.X)[1]);
        engine.fpx.fpcopy(engine.params.B_gen_3_tors, (4 * ind[0] + 2) * engine.params.NWORDS_FIELD, (RS3.Y)[0]);
        engine.fpx.fpcopy(engine.params.B_gen_3_tors, (4 * ind[0] + 3) * engine.params.NWORDS_FIELD, (RS3.Y)[1]);

        engine.isogeny.CompletePoint(P, R);
        Tate3_proj(RS3, R, gX, gZ);
        FinalExpo3(gX, gZ);

        engine.fpx.fp2correction(gX);
        if (!Fpx.subarrayEquals(gX[1], zero, nbytes))    // Not equal to 1
        {
            return true;
        }
        else
        {
            return false;
        }
    }


    protected void FirstPoint3n(long[][] a24, long[][][][] As, long[][] x, PointProjFull R, int[] r, byte[] ind, byte[] bitEll)
    {
        boolean b = false;
        PointProj P = new PointProj(engine.params.NWORDS_FIELD);
        long[] zero = new long[engine.params.NWORDS_FIELD];
        r[0] = 0;

        while (!b)
        {
            bitEll[0] = 0;
            Elligator2(a24, r, 0, x, bitEll, 0, 0);    // Get x-coordinate on curve a24
            engine.fpx.fp2copy(x, P.X);
            engine.fpx.fpcopy(engine.params.Montgomery_one, 0, P.Z[0]);
            engine.fpx.fpcopy(zero, 0, P.Z[1]);
            eval_full_dual_4_isog(As, P);    // Move x over to A = 0
            b = FirstPoint_dual(P, R, ind);  // Compute DLog with 3-torsion points
            r[0] = r[0] + 1;
        }
    }


    protected void SecondPoint3n(long[][] a24, long[][][][] As, long[][] x, PointProjFull R, int[] r, byte[] ind, byte[] bitEll)
    {
        boolean b = false;
        PointProj P = new PointProj(engine.params.NWORDS_FIELD);
        long[] zero = new long[engine.params.NWORDS_FIELD];

        while (!b)
        {
            bitEll[0] = 0;
            Elligator2(a24, r, 1, x, bitEll, 0, 0);
            engine.fpx.fp2copy(x, P.X);
            engine.fpx.fpcopy(engine.params.Montgomery_one, 0, P.Z[0]);
            engine.fpx.fpcopy(zero, 0, P.Z[1]);
            eval_full_dual_4_isog(As, P);    // Move x over to A = 0
            b = SecondPoint_dual(P, R, ind);
            r[1] = r[1] + 1;
        }
    }


    protected void makeDiff(PointProjFull R, PointProjFull S, PointProj D)
    {
        long[][] t0 = new long[2][engine.params.NWORDS_FIELD],
            t1 = new long[2][engine.params.NWORDS_FIELD],
            t2 = new long[2][engine.params.NWORDS_FIELD];
        int nbytes = engine.params.NWORDS_FIELD;

        engine.fpx.fp2sub(R.X, S.X, t0);
        engine.fpx.fp2sub(R.Y, S.Y, t1);
        engine.fpx.fp2sqr_mont(t0, t0);
        engine.fpx.fp2sqr_mont(t1, t1);
        engine.fpx.fp2add(R.X, S.X, t2);
        engine.fpx.fp2mul_mont(t0, t2, t2);
        engine.fpx.fp2sub(t1, t2, t1);
        engine.fpx.fp2mul_mont(D.Z, t1, t1);
        engine.fpx.fp2mul_mont(D.X, t0, t0);
        engine.fpx.fp2correction(t0);
        engine.fpx.fp2correction(t1);
        if (Fpx.subarrayEquals(t0[0], t1[0], nbytes) & Fpx.subarrayEquals(t0[1], t1[1], nbytes))
        {
            engine.fpx.fp2neg(S.Y);
        }
    }


    protected void BuildOrdinary3nBasis_dual(long[][] a24, long[][][][] As, PointProjFull[] R, int[] r, int[] bitsEll, int bitsEllOffset)
    {
        PointProj D = new PointProj(engine.params.NWORDS_FIELD);
        long[][][] xs = new long[2][2][engine.params.NWORDS_FIELD];
        byte[] ind = new byte[1],
            bit = new byte[1];

        FirstPoint3n(a24, As, xs[0], R[0], r, ind, bit);
        bitsEll[bitsEllOffset] = bit[0];
        r[1] = r[0];
        SecondPoint3n(a24, As, xs[1], R[1], r, ind, bit);
        bitsEll[bitsEllOffset] |= ((int)bit[0] << 1);

        // Get x-coordinate of difference
        BiQuad_affine(a24, xs[0], xs[1], D);
        eval_full_dual_4_isog(As, D);    // Move x over to A = 0
        makeDiff(R[0], R[1], D);
    }


    protected void FullIsogeny_A_dual(byte[] PrivateKeyA, long[][][][] As, long[][] a24, int sike)
    {
        // Input:  a private key PrivateKeyA in the range [0, 2^eA - 1]. 
        // Output: the public key PublicKeyA consisting of 3 elements in GF(p^2) which are encoded by removing leading 0 bytes.
        PointProj R = new PointProj(engine.params.NWORDS_FIELD);
        PointProj[] pts = new PointProj[engine.params.MAX_INT_POINTS_ALICE];
        long[][] XPA = new long[2][engine.params.NWORDS_FIELD],
            XQA = new long[2][engine.params.NWORDS_FIELD],
            XRA = new long[2][engine.params.NWORDS_FIELD],
            A24 = new long[2][engine.params.NWORDS_FIELD],
            C24 = new long[2][engine.params.NWORDS_FIELD],
            A = new long[2][engine.params.NWORDS_FIELD];
        long[][][] coeff = new long[5][2][engine.params.NWORDS_FIELD];

        int i, row, m, index = 0, npts = 0, ii = 0;
        int[] pts_index = new int[engine.params.MAX_INT_POINTS_ALICE];
        long[] SecretKeyA = new long[engine.params.NWORDS_ORDER];

        // Initialize basis points
        init_basis(engine.params.A_gen, XPA, XQA, XRA);

        // Initialize constants: A24 = A+2C, C24 = 4C, where A=6, C=1
        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, A24[0]);
        engine.fpx.fp2add(A24, A24, A24);
        engine.fpx.fp2add(A24, A24, C24);
        engine.fpx.fp2add(A24, C24, A);
        engine.fpx.fp2add(C24, C24, A24);

        // Retrieve kernel point
        engine.fpx.decode_to_digits(PrivateKeyA, engine.params.MSG_BYTES, SecretKeyA, engine.params.SECRETKEY_A_BYTES, engine.params.NWORDS_ORDER);
        engine.isogeny.LADDER3PT(XPA, XQA, XRA, SecretKeyA, engine.params.ALICE, R, A);
        engine.fpx.fp2inv_mont(R.Z);
        engine.fpx.fp2mul_mont(R.X, R.Z, R.X);
        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, R.Z[0]);
        engine.fpx.fpzero(R.Z[1]);
        if (sike == 1)
        {
            engine.fpx.fp2_encode(R.X, PrivateKeyA, engine.params.MSG_BYTES + engine.params.SECRETKEY_A_BYTES + engine.params.CRYPTO_PUBLICKEYBYTES);  // privA ||= x(KA) = x(PA + sk_A*QA)
        }
        if (engine.params.OALICE_BITS % 2 == 1)
        {
            PointProj S = new PointProj(engine.params.NWORDS_FIELD);

            engine.isogeny.xDBLe(R, S, A24, C24, (int)(engine.params.OALICE_BITS - 1));
            engine.isogeny.get_2_isog(S, A24, C24);
            engine.isogeny.eval_2_isog(R, S);
            engine.fpx.fp2copy(S.X, As[engine.params.MAX_Alice][2]);
            engine.fpx.fp2copy(S.Z, As[engine.params.MAX_Alice][3]);
        }

        // Traverse tree
        index = 0;
        for (row = 1; row < engine.params.MAX_Alice; row++)
        {
            while (index < engine.params.MAX_Alice - row)
            {
                pts[npts] = new PointProj(engine.params.NWORDS_FIELD);
                engine.fpx.fp2copy(R.X, pts[npts].X);
                engine.fpx.fp2copy(R.Z, pts[npts].Z);
                pts_index[npts++] = index;
                m = engine.params.strat_Alice[ii++];
                engine.isogeny.xDBLe(R, R, A24, C24, (int)(2 * m));
                index += m;
            }

            engine.fpx.fp2copy(A24, As[row - 1][0]);
            engine.fpx.fp2copy(C24, As[row - 1][1]);
            get_4_isog_dual(R, A24, C24, coeff);
            for (i = 0; i < npts; i++)
            {
                engine.isogeny.eval_4_isog(pts[i], coeff);
            }
            eval_dual_4_isog_shared(coeff[2], coeff[3], coeff[4], As[row - 1], 2);
            engine.fpx.fp2copy(pts[npts - 1].X, R.X);
            engine.fpx.fp2copy(pts[npts - 1].Z, R.Z);
            index = pts_index[npts - 1];
            npts -= 1;
        }
        engine.fpx.fp2copy(A24, As[engine.params.MAX_Alice - 1][0]);
        engine.fpx.fp2copy(C24, As[engine.params.MAX_Alice - 1][1]);

        get_4_isog_dual(R, A24, C24, coeff);
        eval_dual_4_isog_shared(coeff[2], coeff[3], coeff[4], As[engine.params.MAX_Alice - 1], 2);
        engine.fpx.fp2copy(A24, As[engine.params.MAX_Alice][0]);
        engine.fpx.fp2copy(C24, As[engine.params.MAX_Alice][1]);
        engine.fpx.fp2inv_mont_bingcd(C24);
        engine.fpx.fp2mul_mont(A24, C24, a24);
    }


    protected void Dlogs3_dual(long[][][] f, int[] D, long[] d0, long[] c0, long[] d1, long[] c1)
    {
        solve_dlog(f[0], D, d0, 3);
        solve_dlog(f[2], D, c0, 3);
        solve_dlog(f[1], D, d1, 3);
        solve_dlog(f[3], D, c1, 3);
        engine.fpx.mp_sub(engine.params.Bob_order, c0, c0, engine.params.NWORDS_ORDER);
        engine.fpx.mp_sub(engine.params.Bob_order, c1, c1, engine.params.NWORDS_ORDER);
    }


    protected void BuildOrdinary3nBasis_Decomp_dual(long[][] A24, PointProj[] Rs, int[] r, int[] bitsEll, int bitsEllIndex)
    {
        byte[] bitEll = new byte[2];

        bitEll[0] = (byte)(bitsEll[bitsEllIndex] & 0x1);
        bitEll[1] = (byte)((bitsEll[bitsEllIndex] >>> 1) & 0x1);

        // Elligator2 both x-coordinates
        r[0] -= 1;
        Elligator2(A24, r, 0, Rs[0].X, bitEll, 0, 1);
        r[1] -= 1;
        Elligator2(A24, r, 1, Rs[1].X, bitEll, 1, 1);
        // Get x-coordinate of difference
        BiQuad_affine(A24, Rs[0].X, Rs[1].X, Rs[2]);
    }


    protected void PKADecompression_dual(byte[] SecretKeyB, byte[] CompressedPKA, PointProj R, long[][] A)
    {
        byte bit;
        int[] rs = new int[3];
        long[][] A24 = new long[2][engine.params.NWORDS_FIELD];
        PointProj[] Rs = new PointProj[3];
        Rs[0] = new PointProj(engine.params.NWORDS_FIELD);
        Rs[1] = new PointProj(engine.params.NWORDS_FIELD);
        Rs[2] = new PointProj(engine.params.NWORDS_FIELD);


        long[] t1 = new long[engine.params.NWORDS_ORDER],
            t2 = new long[engine.params.NWORDS_ORDER],
            t3 = new long[engine.params.NWORDS_ORDER],
            t4 = new long[engine.params.NWORDS_ORDER],
            vone = new long[engine.params.NWORDS_ORDER],
            temp = new long[engine.params.NWORDS_ORDER],
            SKin = new long[engine.params.NWORDS_ORDER];


        engine.fpx.fp2_decode(CompressedPKA, A, 3 * engine.params.ORDER_B_ENCODED_BYTES);
        vone[0] = 1;
        engine.fpx.to_Montgomery_mod_order(vone, vone, engine.params.Bob_order, engine.params.Montgomery_RB2, engine.params.Montgomery_RB1);  // Converting to Montgomery representation
        bit = (byte)((CompressedPKA[3 * engine.params.ORDER_B_ENCODED_BYTES + engine.params.FP2_ENCODED_BYTES] & 0xff) >> 7);

        byte[] rs_temp = new byte[3];
        System.arraycopy(CompressedPKA, 3 * engine.params.ORDER_B_ENCODED_BYTES + engine.params.FP2_ENCODED_BYTES, rs_temp, 0, 3);
        rs[0] = rs_temp[0] & 0xffff;
        rs[1] = rs_temp[1] & 0xffff;
        rs[2] = rs_temp[2] & 0xffff;

        rs[0] &= 0x7F;

        engine.fpx.fpaddPRIME(A[0], engine.params.Montgomery_one, A24[0]);
        engine.fpx.fpcopy(A[1], 0, A24[1]);
        engine.fpx.fpaddPRIME(A24[0], engine.params.Montgomery_one, A24[0]);
        engine.fpx.fp2div2(A24, A24);
        engine.fpx.fp2div2(A24, A24);

        BuildOrdinary3nBasis_Decomp_dual(A24, Rs, rs, rs, 2);
        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, Rs[0].Z[0]);
        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, Rs[1].Z[0]);

        engine.isogeny.swap_points(Rs[0], Rs[1], -(long)bit);
        engine.fpx.decode_to_digits(SecretKeyB, 0, SKin, engine.params.SECRETKEY_B_BYTES, engine.params.NWORDS_ORDER);
        engine.fpx.to_Montgomery_mod_order(SKin, t1, engine.params.Bob_order, engine.params.Montgomery_RB2, engine.params.Montgomery_RB1);    // Converting to Montgomery representation
        engine.fpx.decode_to_digits(CompressedPKA, 0, temp, engine.params.ORDER_B_ENCODED_BYTES, engine.params.NWORDS_ORDER);
        engine.fpx.to_Montgomery_mod_order(temp, t2, engine.params.Bob_order, engine.params.Montgomery_RB2, engine.params.Montgomery_RB1);
        engine.fpx.decode_to_digits(CompressedPKA, engine.params.ORDER_B_ENCODED_BYTES, temp, engine.params.ORDER_B_ENCODED_BYTES, engine.params.NWORDS_ORDER);
        engine.fpx.to_Montgomery_mod_order(temp, t3, engine.params.Bob_order, engine.params.Montgomery_RB2, engine.params.Montgomery_RB1);
        engine.fpx.decode_to_digits(CompressedPKA, 2 * engine.params.ORDER_B_ENCODED_BYTES, temp, engine.params.ORDER_B_ENCODED_BYTES, engine.params.NWORDS_ORDER);
        engine.fpx.to_Montgomery_mod_order(temp, t4, engine.params.Bob_order, engine.params.Montgomery_RB2, engine.params.Montgomery_RB1);

        if (bit == 0)
        {
            engine.fpx.Montgomery_multiply_mod_order(t1, t3, t3, engine.params.Bob_order, engine.params.Montgomery_RB2);
            engine.fpx.mp_add(t3, vone, t3, engine.params.NWORDS_ORDER);
            engine.fpx.Montgomery_inversion_mod_order_bingcd(t3, t3, engine.params.Bob_order, engine.params.Montgomery_RB2, engine.params.Montgomery_RB1);
            engine.fpx.Montgomery_multiply_mod_order(t1, t4, t4, engine.params.Bob_order, engine.params.Montgomery_RB2);
            engine.fpx.mp_add(t2, t4, t4, engine.params.NWORDS_ORDER);
            engine.fpx.Montgomery_multiply_mod_order(t3, t4, t3, engine.params.Bob_order, engine.params.Montgomery_RB2);
            engine.fpx.from_Montgomery_mod_order(t3, t3, engine.params.Bob_order, engine.params.Montgomery_RB2);    // Converting back from Montgomery representation
            Ladder3pt_dual(Rs, t3, engine.params.BOB, R, A24);
        }
        else
        {
            engine.fpx.Montgomery_multiply_mod_order(t1, t4, t4, engine.params.Bob_order, engine.params.Montgomery_RB2);
            engine.fpx.mp_add(t4, vone, t4, engine.params.NWORDS_ORDER);
            engine.fpx.Montgomery_inversion_mod_order_bingcd(t4, t4, engine.params.Bob_order, engine.params.Montgomery_RB2, engine.params.Montgomery_RB1);
            engine.fpx.Montgomery_multiply_mod_order(t1, t3, t3, engine.params.Bob_order, engine.params.Montgomery_RB2);
            engine.fpx.mp_add(t2, t3, t3, engine.params.NWORDS_ORDER);
            engine.fpx.Montgomery_multiply_mod_order(t3, t4, t3, engine.params.Bob_order, engine.params.Montgomery_RB2);
            engine.fpx.from_Montgomery_mod_order(t3, t3, engine.params.Bob_order, engine.params.Montgomery_RB2);    // Converting back from Montgomery representation
            Ladder3pt_dual(Rs, t3, engine.params.BOB, R, A24);
        }
        engine.isogeny.Double(R, R, A24, engine.params.OALICE_BITS);    // x, z := Double(A24, x, 1, eA);
    }


    protected void Compress_PKA_dual(long[] d0, long[] c0, long[] d1, long[] c1, long[][] a24, int[] rs, byte[] CompressedPKA)
    {
        int bit;
        long[] temp = new long[engine.params.NWORDS_ORDER],
            inv = new long[engine.params.NWORDS_ORDER];
        long[][] A = new long[2][engine.params.NWORDS_FIELD];

        engine.fpx.fp2add(a24, a24, A);
        engine.fpx.fp2add(A, A, A);
        engine.fpx.fpsubPRIME(A[0], engine.params.Montgomery_one, A[0]);
        engine.fpx.fpsubPRIME(A[0], engine.params.Montgomery_one, A[0]);    // 4*a24-2

        bit = engine.fpx.mod3(d1);
        engine.fpx.to_Montgomery_mod_order(c0, c0, engine.params.Bob_order, engine.params.Montgomery_RB2, engine.params.Montgomery_RB1);   // Converting to Montgomery representation
        engine.fpx.to_Montgomery_mod_order(c1, c1, engine.params.Bob_order, engine.params.Montgomery_RB2, engine.params.Montgomery_RB1);
        engine.fpx.to_Montgomery_mod_order(d0, d0, engine.params.Bob_order, engine.params.Montgomery_RB2, engine.params.Montgomery_RB1);
        engine.fpx.to_Montgomery_mod_order(d1, d1, engine.params.Bob_order, engine.params.Montgomery_RB2, engine.params.Montgomery_RB1);

        if (bit != 0)
        {  // Storing [d1*c0inv, c1*c0inv, d0*c0inv] and setting bit "NBITS_ORDER" to 0
            engine.fpx.Montgomery_inversion_mod_order_bingcd(d1, inv, engine.params.Bob_order, engine.params.Montgomery_RB2, engine.params.Montgomery_RB1);
            engine.fpx.Montgomery_neg(d0, engine.params.Bob_order);
            engine.fpx.Montgomery_multiply_mod_order(d0, inv, temp, engine.params.Bob_order, engine.params.Montgomery_RB2);
            engine.fpx.from_Montgomery_mod_order(temp, temp, engine.params.Bob_order, engine.params.Montgomery_RB2);                    // Converting back from Montgomery representation
            engine.fpx.encode_to_bytes(temp, CompressedPKA, 0, engine.params.ORDER_B_ENCODED_BYTES);
            engine.fpx.Montgomery_neg(c1, engine.params.Bob_order);
            engine.fpx.Montgomery_multiply_mod_order(c1, inv, temp, engine.params.Bob_order, engine.params.Montgomery_RB2);
            engine.fpx.from_Montgomery_mod_order(temp, temp, engine.params.Bob_order, engine.params.Montgomery_RB2);
            engine.fpx.encode_to_bytes(temp, CompressedPKA, engine.params.ORDER_B_ENCODED_BYTES, engine.params.ORDER_B_ENCODED_BYTES);
            engine.fpx.Montgomery_multiply_mod_order(c0, inv, temp, engine.params.Bob_order, engine.params.Montgomery_RB2);
            engine.fpx.from_Montgomery_mod_order(temp, temp, engine.params.Bob_order, engine.params.Montgomery_RB2);
            engine.fpx.encode_to_bytes(temp, CompressedPKA, 2 * engine.params.ORDER_B_ENCODED_BYTES, engine.params.ORDER_B_ENCODED_BYTES);
            CompressedPKA[3 * engine.params.ORDER_B_ENCODED_BYTES + engine.params.FP2_ENCODED_BYTES] = 0x00;
        }
        else
        {  // Storing [d1*d0inv, c1*d0inv, c0*d0inv] and setting bit "NBITS_ORDER" to 1
            engine.fpx.Montgomery_inversion_mod_order_bingcd(d0, inv, engine.params.Bob_order, engine.params.Montgomery_RB2, engine.params.Montgomery_RB1);
            engine.fpx.Montgomery_neg(d1, engine.params.Bob_order);
            engine.fpx.Montgomery_multiply_mod_order(d1, inv, temp, engine.params.Bob_order, engine.params.Montgomery_RB2);
            engine.fpx.from_Montgomery_mod_order(temp, temp, engine.params.Bob_order, engine.params.Montgomery_RB2);                     // Converting back from Montgomery representation
            engine.fpx.encode_to_bytes(temp, CompressedPKA, 0, engine.params.ORDER_B_ENCODED_BYTES);
            engine.fpx.Montgomery_multiply_mod_order(c1, inv, temp, engine.params.Bob_order, engine.params.Montgomery_RB2);
            engine.fpx.from_Montgomery_mod_order(temp, temp, engine.params.Bob_order, engine.params.Montgomery_RB2);
            engine.fpx.encode_to_bytes(temp, CompressedPKA, engine.params.ORDER_B_ENCODED_BYTES, engine.params.ORDER_B_ENCODED_BYTES);
            engine.fpx.Montgomery_neg(c0, engine.params.Bob_order);
            engine.fpx.Montgomery_multiply_mod_order(c0, inv, temp, engine.params.Bob_order, engine.params.Montgomery_RB2);
            engine.fpx.from_Montgomery_mod_order(temp, temp, engine.params.Bob_order, engine.params.Montgomery_RB2);
            engine.fpx.encode_to_bytes(temp, CompressedPKA, 2 * engine.params.ORDER_B_ENCODED_BYTES, engine.params.ORDER_B_ENCODED_BYTES);
            CompressedPKA[3 * engine.params.ORDER_B_ENCODED_BYTES + engine.params.FP2_ENCODED_BYTES] = (byte)0x80;
        }

        engine.fpx.fp2_encode(A, CompressedPKA, 3 * engine.params.ORDER_B_ENCODED_BYTES);
        CompressedPKA[3 * engine.params.ORDER_B_ENCODED_BYTES + engine.params.FP2_ENCODED_BYTES] |= (byte)rs[0];
        CompressedPKA[3 * engine.params.ORDER_B_ENCODED_BYTES + engine.params.FP2_ENCODED_BYTES + 1] = (byte)rs[1];
        CompressedPKA[3 * engine.params.ORDER_B_ENCODED_BYTES + engine.params.FP2_ENCODED_BYTES + 2] = (byte)rs[2];
    }

    // Alice's ephemeral public key generation using compression -- SIKE protocol
    // Output: PrivateKeyA[MSG_BYTES + engine.params.SECRETKEY_A_BYTES] <- x(K_A) where K_A = PA + sk_A*Q_A
    protected int EphemeralKeyGeneration_A_extended(byte[] PrivateKeyA, byte[] CompressedPKA)
    {
        int[] rs = new int[3],
            D = new int[engine.params.DLEN_3];
        long[][] a24 = new long[2][engine.params.NWORDS_FIELD];
        long[][][][] As = new long[engine.params.MAX_Alice + 1][5][2][engine.params.NWORDS_FIELD];
        long[][][] f = new long[4][2][engine.params.NWORDS_FIELD];
        long[] c0 = new long[engine.params.NWORDS_ORDER],
            d0 = new long[engine.params.NWORDS_ORDER],
            c1 = new long[engine.params.NWORDS_ORDER],
            d1 = new long[engine.params.NWORDS_ORDER];
        PointProjFull[] Rs = new PointProjFull[2];
        Rs[0] = new PointProjFull(engine.params.NWORDS_FIELD);
        Rs[1] = new PointProjFull(engine.params.NWORDS_FIELD);

        FullIsogeny_A_dual(PrivateKeyA, As, a24, 1);
        BuildOrdinary3nBasis_dual(a24, As, Rs, rs, rs, 2);
        Tate3_pairings(Rs, f);
        Dlogs3_dual(f, D, d0, c0, d1, c1);
        Compress_PKA_dual(d0, c0, d1, c1, a24, rs, CompressedPKA);
        return 0;
    }

    // Alice's ephemeral public key generation using compression -- SIDH protocol
    // Output: PrivateKeyA[MSG_BYTES + engine.params.SECRETKEY_A_BYTES] <- x(K_A) where K_A = PA + sk_A*Q_A
//    private int EphemeralKeyGeneration_A(byte[] PrivateKeyA, byte[] CompressedPKA)
//    {
//        int[] rs = new int[3],
//              D = new int[engine.params.DLEN_3];
//        long[] c0 = new long[engine.params.NWORDS_ORDER],
//               d0 = new long[engine.params.NWORDS_ORDER],
//               c1 = new long[engine.params.NWORDS_ORDER],
//               d1 = new long[engine.params.NWORDS_ORDER];
//        long[][] a24 = new long[2][engine.params.NWORDS_FIELD];
//        long[][][] f = new long[4][2][engine.params.NWORDS_FIELD];
//        long[][][][] As = new long[engine.params.MAX_Alice+1][5][2][engine.params.NWORDS_FIELD];
//        PointProjFull[] Rs = new PointProjFull[2];
//
//        FullIsogeny_A_dual(PrivateKeyA, As, a24, 0);
//        BuildOrdinary3nBasis_dual(a24, As, Rs, rs, rs, 2);
//        Tate3_pairings(Rs, f);
//        Dlogs3_dual(f, D, d0, c0, d1, c1);
//        Compress_PKA_dual(d0, c0, d1, c1, a24, rs, CompressedPKA);
//        return 0;
//    }

    // Bob's ephemeral shared secret computation using compression
    // It produces a shared secret key SharedSecretB using his secret key PrivateKeyB and Alice's decompressed data point_R and param_A
    // Inputs: Bob's PrivateKeyB is an integer in the range [1, oB-1], where oB = 3^OBOB_EXP.
    //         Alice's decompressed data consists of point_R in (X:Z) coordinates and the curve parameter param_A in GF(p^2).
    // Output: a shared secret SharedSecretB that consists of one element in GF(p^2).
    int EphemeralSecretAgreement_B(byte[] PrivateKeyB, byte[] PKA, byte[] SharedSecretB)
    {
        int i, ii = 0, row, m, index = 0, npts = 0;
        int[] pts_index = new int[engine.params.MAX_INT_POINTS_BOB];
        long[][] A24plus = new long[2][engine.params.NWORDS_FIELD],
            A24minus = new long[2][engine.params.NWORDS_FIELD];
        PointProj R = new PointProj(engine.params.NWORDS_FIELD);
        PointProj[] pts = new PointProj[engine.params.MAX_INT_POINTS_BOB];
        long[][] jinv = new long[2][engine.params.NWORDS_FIELD], A = new long[2][engine.params.NWORDS_FIELD];
        long[][][] coeff = new long[3][2][engine.params.NWORDS_FIELD];
        long[][] param_A = new long[2][engine.params.NWORDS_FIELD];

        PKADecompression_dual(PrivateKeyB, PKA, R, param_A);
        engine.fpx.fp2copy(param_A, A);
        engine.fpx.fpaddPRIME(engine.params.Montgomery_one, engine.params.Montgomery_one, A24minus[0]);
        engine.fpx.fp2add(A, A24minus, A24plus);
        engine.fpx.fp2sub(A, A24minus, A24minus);

        // Traverse tree
        index = 0;
        for (row = 1; row < engine.params.MAX_Bob; row++)
        {
            while (index < engine.params.MAX_Bob - row)
            {
                pts[npts] = new PointProj(engine.params.NWORDS_FIELD);
                engine.fpx.fp2copy(R.X, pts[npts].X);
                engine.fpx.fp2copy(R.Z, pts[npts].Z);
                pts_index[npts++] = index;
                m = engine.params.strat_Bob[ii++];
                engine.isogeny.xTPLe(R, R, A24minus, A24plus, (int)m);
                index += m;
            }
            engine.isogeny.get_3_isog(R, A24minus, A24plus, coeff);

            for (i = 0; i < npts; i++)
            {
                engine.isogeny.eval_3_isog(pts[i], coeff);
            }

            engine.fpx.fp2copy(pts[npts - 1].X, R.X);
            engine.fpx.fp2copy(pts[npts - 1].Z, R.Z);
            index = pts_index[npts - 1];
            npts -= 1;
        }

        engine.isogeny.get_3_isog(R, A24minus, A24plus, coeff);
        engine.fpx.fp2add(A24plus, A24minus, A);
        engine.fpx.fp2add(A, A, A);
        engine.fpx.fp2sub(A24plus, A24minus, A24plus);
        engine.isogeny.j_inv(A, A24plus, jinv);
        engine.fpx.fp2_encode(jinv, SharedSecretB, 0);    // Format shared secret

        return 0;
    }


    protected void BuildEntangledXonly(long[][] A, PointProj[] R, byte[] qnr, byte[] ind)
    {
        long[] s = new long[engine.params.NWORDS_FIELD];
        long[][] t_ptr, r = new long[2][engine.params.NWORDS_FIELD],
            t = new long[2][engine.params.NWORDS_FIELD];
        int t_ptrOffset = 0;

        // Select the correct table
        if (engine.fpx.is_sqr_fp2(A, s))
        {
            t_ptr = engine.params.table_v_qnr;
            qnr[0] = 1;
        }
        else
        {
            t_ptr = engine.params.table_v_qr;
            qnr[0] = 0;
        }

        // Get x0
        ind[0] = 0;
        do
        {
            engine.fpx.fp2mul_mont(A, t_ptr, t_ptrOffset, R[0].X);    // R[0].X =  A*v
            t_ptrOffset += 2;
            engine.fpx.fp2neg(R[0].X);                                  // R[0].X = -A*v
            engine.fpx.fp2add(R[0].X, A, t);
            engine.fpx.fp2mul_mont(R[0].X, t, t);
            engine.fpx.fpaddPRIME(t[0], engine.params.Montgomery_one, t[0]);
            engine.fpx.fp2mul_mont(R[0].X, t, t);                     // t = R[0].X^3 + A*R[0].X^2 + R[0].X
            ind[0] += 1;
        }
        while (!engine.fpx.is_sqr_fp2(t, s));
        ind[0] -= 1;

        if (qnr[0] == 1)
        {
            engine.fpx.fpcopy(engine.params.table_r_qnr[ind[0]], 0, r[0]);
        }
        else
        {
            engine.fpx.fpcopy(engine.params.table_r_qr[ind[0]], 0, r[0]);
        }

        // Get x1
        engine.fpx.fp2add(R[0].X, A, R[1].X);
        engine.fpx.fp2neg(R[1].X);    // R[1].X = -R[0].X-A

        // Get difference x2,  z2
        engine.fpx.fp2sub(R[0].X, R[1].X, R[2].Z);
        engine.fpx.fp2sqr_mont(R[2].Z, R[2].Z);

        engine.fpx.fpcopy(r[0], 0, r[1]);    // (1+i)*ind
        engine.fpx.fpaddPRIME(engine.params.Montgomery_one, r[0], r[0]);
        engine.fpx.fp2sqr_mont(r, r);
        engine.fpx.fp2mul_mont(t, r, R[2].X);
    }


    protected void RecoverY(long[][] A, PointProj[] xs, PointProjFull[] Rs)
    {
        long[][] t0 = new long[2][engine.params.NWORDS_FIELD],
            t1 = new long[2][engine.params.NWORDS_FIELD],
            t2 = new long[2][engine.params.NWORDS_FIELD],
            t3 = new long[2][engine.params.NWORDS_FIELD],
            t4 = new long[2][engine.params.NWORDS_FIELD];

        engine.fpx.fp2mul_mont(xs[2].X, xs[1].Z, t0);
        engine.fpx.fp2mul_mont(xs[1].X, xs[2].Z, t1);
        engine.fpx.fp2mul_mont(xs[1].X, xs[2].X, t2);
        engine.fpx.fp2mul_mont(xs[1].Z, xs[2].Z, t3);
        engine.fpx.fp2sqr_mont(xs[1].X, t4);
        engine.fpx.fp2sqr_mont(xs[1].Z, Rs[1].X);
        engine.fpx.fp2sub(t2, t3, Rs[1].Y);
        engine.fpx.fp2mul_mont(xs[1].X, Rs[1].Y, Rs[1].Y);
        engine.fpx.fp2add(t4, Rs[1].X, t4);
        engine.fpx.fp2mul_mont(xs[2].Z, t4, t4);
        engine.fpx.fp2mul_mont(A, t1, Rs[1].X);
        engine.fpx.fp2sub(t0, t1, Rs[1].Z);

        engine.fpx.fp2mul_mont(Rs[0].X, Rs[1].Z, t0);
        engine.fpx.fp2add(t2, Rs[1].X, t1);
        engine.fpx.fp2add(t1, t1, t1);
        engine.fpx.fp2sub(t0, t1, t0);
        engine.fpx.fp2mul_mont(xs[1].Z, t0, t0);
        engine.fpx.fp2sub(t0, t4, t0);
        engine.fpx.fp2mul_mont(Rs[0].X, t0, t0);
        engine.fpx.fp2add(t0, Rs[1].Y, Rs[1].Y);
        engine.fpx.fp2mul_mont(Rs[0].Y, t3, t0);
        engine.fpx.fp2mul_mont(xs[1].X, t0, Rs[1].X);
        engine.fpx.fp2add(Rs[1].X, Rs[1].X, Rs[1].X);
        engine.fpx.fp2mul_mont(xs[1].Z, t0, Rs[1].Z);
        engine.fpx.fp2add(Rs[1].Z, Rs[1].Z, Rs[1].Z);

        engine.fpx.fp2inv_mont_bingcd(Rs[1].Z);
        engine.fpx.fp2mul_mont(Rs[1].X, Rs[1].Z, Rs[1].X);
        engine.fpx.fp2mul_mont(Rs[1].Y, Rs[1].Z, Rs[1].Y);
    }


    protected void BuildOrdinary2nBasis_dual(long[][] A, long[][][][] Ds, PointProjFull[] Rs, byte[] qnr, byte[] ind)
    {
        int i;
        long[] t0 = new long[engine.params.NWORDS_FIELD];
        long[][] A6 = new long[2][engine.params.NWORDS_FIELD];
        PointProj[] xs = new PointProj[3];
        xs[0] = new PointProj(engine.params.NWORDS_FIELD);
        xs[1] = new PointProj(engine.params.NWORDS_FIELD);
        xs[2] = new PointProj(engine.params.NWORDS_FIELD);

        // Generate x-only entangled basis 
        BuildEntangledXonly(A, xs, qnr, ind);
        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, (xs[0].Z)[0]);
        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, (xs[1].Z)[0]);

        // Move them back to A = 6 
        for (i = 0; i < engine.params.MAX_Bob; i++)
        {
            engine.isogeny.eval_3_isog(xs[0], Ds[engine.params.MAX_Bob - 1 - i]);
            engine.isogeny.eval_3_isog(xs[1], Ds[engine.params.MAX_Bob - 1 - i]);
            engine.isogeny.eval_3_isog(xs[2], Ds[engine.params.MAX_Bob - 1 - i]);
        }

        // Recover y-coordinates with a single sqrt on A = 6
        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, A6[0]);
        engine.fpx.fpaddPRIME(A6[0], A6[0], t0);
        engine.fpx.fpaddPRIME(t0, t0, A6[0]);
        engine.fpx.fpaddPRIME(A6[0], t0, A6[0]);    // A6 = 6 

        engine.isogeny.CompleteMPoint(A6, xs[0], Rs[0]);
        RecoverY(A6, xs, Rs);
    }

    // Bob's ephemeral public key generation
    // Input:  a private key PrivateKeyB in the range [0, 2^Floor(Log(2,oB)) - 1].
    // Output: the public key PublicKeyB consisting of 3 elements in GF(p^2) which are encoded by removing leading 0 bytes.
    protected void FullIsogeny_B_dual(byte[] PrivateKeyB, long[][][][] Ds, long[][] A)
    {
        PointProj R = new PointProj(engine.params.NWORDS_FIELD),
            Q3 = new PointProj(engine.params.NWORDS_FIELD);
        PointProj[] pts = new PointProj[engine.params.MAX_INT_POINTS_BOB];

        long[][] XPB = new long[2][engine.params.NWORDS_FIELD],
            XQB = new long[2][engine.params.NWORDS_FIELD],
            XRB = new long[2][engine.params.NWORDS_FIELD],
            A24plus = new long[2][engine.params.NWORDS_FIELD],
            A24minus = new long[2][engine.params.NWORDS_FIELD];
        long[][][] coeff = new long[3][2][engine.params.NWORDS_FIELD];
        int i, row, m, index = 0, npts = 0, ii = 0;
        int[] pts_index = new int[engine.params.MAX_INT_POINTS_BOB];
        long[] SecretKeyB = new long[engine.params.NWORDS_ORDER];

        // Initialize basis points
        init_basis(engine.params.B_gen, XPB, XQB, XRB);
        engine.fpx.fpcopy(engine.params.XQB3, 0, Q3.X[0]);
        engine.fpx.fpcopy(engine.params.XQB3, engine.params.NWORDS_FIELD, (Q3.X)[1]);
        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, Q3.Z[0]);

        // Initialize constants: A24minus = A-2C, A24plus = A+2C, where A=6, C=1
        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, A24plus[0]);
        engine.fpx.fp2add(A24plus, A24plus, A24plus);
        engine.fpx.fp2add(A24plus, A24plus, A24minus);
        engine.fpx.fp2add(A24plus, A24minus, A);
        engine.fpx.fp2add(A24minus, A24minus, A24plus);

        // Retrieve kernel point
        engine.fpx.decode_to_digits(PrivateKeyB, 0, SecretKeyB, engine.params.SECRETKEY_B_BYTES, engine.params.NWORDS_ORDER);
        engine.isogeny.LADDER3PT(XPB, XQB, XRB, SecretKeyB, engine.params.BOB, R, A);

        // Traverse tree
        index = 0;
        for (row = 1; row < engine.params.MAX_Bob; row++)
        {
            while (index < engine.params.MAX_Bob - row)
            {
                pts[npts] = new PointProj(engine.params.NWORDS_FIELD);
                engine.fpx.fp2copy(R.X, pts[npts].X);
                engine.fpx.fp2copy(R.Z, pts[npts].Z);
                pts_index[npts++] = index;
                m = engine.params.strat_Bob[ii++];
                engine.isogeny.xTPLe(R, R, A24minus, A24plus, (int)m);
                index += m;
            }
            engine.isogeny.get_3_isog(R, A24minus, A24plus, coeff);
            for (i = 0; i < npts; i++)
            {
                engine.isogeny.eval_3_isog(pts[i], coeff);
            }
            engine.isogeny.eval_3_isog(Q3, coeff);    // Kernel of dual 
            engine.fpx.fp2sub(Q3.X, Q3.Z, Ds[row - 1][0]);
            engine.fpx.fp2add(Q3.X, Q3.Z, Ds[row - 1][1]);

            engine.fpx.fp2copy(pts[npts - 1].X, R.X);
            engine.fpx.fp2copy(pts[npts - 1].Z, R.Z);
            index = pts_index[npts - 1];
            npts -= 1;
        }
        engine.isogeny.get_3_isog(R, A24minus, A24plus, coeff);
        engine.isogeny.eval_3_isog(Q3, coeff);    // Kernel of dual 
        engine.fpx.fp2sub(Q3.X, Q3.Z, Ds[engine.params.MAX_Bob - 1][0]);
        engine.fpx.fp2add(Q3.X, Q3.Z, Ds[engine.params.MAX_Bob - 1][1]);

        engine.fpx.fp2add(A24plus, A24minus, A);
        engine.fpx.fp2sub(A24plus, A24minus, A24plus);
        engine.fpx.fp2inv_mont_bingcd(A24plus);
        engine.fpx.fp2mul_mont(A24plus, A, A);
        engine.fpx.fp2add(A, A, A);    // A = 2*(A24plus+A24mins)/(A24plus-A24minus) 
    }


    protected void Dlogs2_dual(long[][][] f, int[] D, long[] d0, long[] c0, long[] d1, long[] c1)
    {
        solve_dlog(f[0], D, d0, 2);
        solve_dlog(f[2], D, c0, 2);
        solve_dlog(f[1], D, d1, 2);
        solve_dlog(f[3], D, c1, 2);
        engine.fpx.mp_sub(engine.params.Alice_order, c0, c0, engine.params.NWORDS_ORDER);
        engine.fpx.mp_sub(engine.params.Alice_order, c1, c1, engine.params.NWORDS_ORDER);
    }


    protected void BuildEntangledXonly_Decomp(long[][] A, PointProj[] R, int qnr, int ind)
    {
        long[][] t_ptr, r = new long[2][engine.params.NWORDS_FIELD], t = new long[2][engine.params.NWORDS_FIELD];

        // Select the correct table
        if (qnr == 1)
        {
            t_ptr = engine.params.table_v_qnr;
        }
        else
        {
            t_ptr = engine.params.table_v_qr;
        }

        if (ind >= engine.params.TABLE_V_LEN / 2)
        {
            ind = 0;
        }
        // Get x0     
        engine.fpx.fp2mul_mont(A, t_ptr, ind * 2, R[0].X);    // x1 =  A*v
        engine.fpx.fp2neg(R[0].X);                        // R[0].X = -A*v
        engine.fpx.fp2add(R[0].X, A, t);
        engine.fpx.fp2mul_mont(R[0].X, t, t);
        engine.fpx.fpaddPRIME(t[0], engine.params.Montgomery_one, t[0]);
        engine.fpx.fp2mul_mont(R[0].X, t, t);             // t = R[0].X^3 + A*R[0].X^2 + R[0].X

        if (qnr == 1)
        {
            engine.fpx.fpcopy(engine.params.table_r_qnr[ind], 0, r[0]);
        }
        else
        {
            engine.fpx.fpcopy(engine.params.table_r_qr[ind], 0, r[0]);
        }

        // Get x1 
        engine.fpx.fp2add(R[0].X, A, R[1].X);
        engine.fpx.fp2neg(R[1].X);    // R[1].X = -R[0].X-A

        // Get difference x2,z2 
        engine.fpx.fp2sub(R[0].X, R[1].X, R[2].Z);
        engine.fpx.fp2sqr_mont(R[2].Z, R[2].Z);

        engine.fpx.fpcopy(r[0], 0, r[1]); // (1+i)*ind
        engine.fpx.fpaddPRIME(engine.params.Montgomery_one, r[0], r[0]);
        engine.fpx.fp2sqr_mont(r, r);
        engine.fpx.fp2mul_mont(t, r, R[2].X);
    }

    // Bob's PK decompression -- SIKE protocol
    protected void PKBDecompression_extended(byte[] SecretKeyA, int SecretKeyAOffset, byte[] CompressedPKB, PointProj R, long[][] A, byte[] tphiBKA_t, int tphiBKA_tOffset)
    {
        long mask = -1L;
        int qnr, ind;
        long[][] A24 = new long[2][engine.params.NWORDS_FIELD],
            Adiv2 = new long[2][engine.params.NWORDS_FIELD];
        long[] tmp1 = new long[2 * engine.params.NWORDS_ORDER],
            tmp2 = new long[2 * engine.params.NWORDS_ORDER],
            inv = new long[engine.params.NWORDS_ORDER],
            scal = new long[2 * engine.params.NWORDS_ORDER],
            SKin = new long[engine.params.NWORDS_ORDER],
            a0 = new long[engine.params.NWORDS_ORDER],
            a1 = new long[engine.params.NWORDS_ORDER],
            b0 = new long[engine.params.NWORDS_ORDER],
            b1 = new long[engine.params.NWORDS_ORDER];
        PointProj[] Rs = new PointProj[3];
        Rs[0] = new PointProj(engine.params.NWORDS_FIELD);
        Rs[1] = new PointProj(engine.params.NWORDS_FIELD);
        Rs[2] = new PointProj(engine.params.NWORDS_FIELD);

        mask >>>= (engine.params.MAXBITS_ORDER - engine.params.OALICE_BITS);

        engine.fpx.fp2_decode(CompressedPKB, A, 4 * engine.params.ORDER_A_ENCODED_BYTES);
        qnr = CompressedPKB[4 * engine.params.ORDER_A_ENCODED_BYTES + engine.params.FP2_ENCODED_BYTES] & 0x01;
        ind = CompressedPKB[4 * engine.params.ORDER_A_ENCODED_BYTES + engine.params.FP2_ENCODED_BYTES + 1];
        BuildEntangledXonly_Decomp(A, Rs, qnr, ind);
        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, Rs[0].Z[0]);
        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, Rs[1].Z[0]);

        engine.fpx.fpaddPRIME(A[0], engine.params.Montgomery_one, A24[0]);
        engine.fpx.fpcopy(A[1], 0, A24[1]);
        engine.fpx.fpaddPRIME(A24[0], engine.params.Montgomery_one, A24[0]);
        engine.fpx.fp2div2(A24, A24);
        engine.fpx.fp2div2(A24, A24);

        engine.fpx.decode_to_digits(SecretKeyA, SecretKeyAOffset, SKin, engine.params.SECRETKEY_A_BYTES, engine.params.NWORDS_ORDER);
        engine.fpx.decode_to_digits(CompressedPKB, 0, a0, engine.params.ORDER_A_ENCODED_BYTES, engine.params.NWORDS_ORDER);
        engine.fpx.decode_to_digits(CompressedPKB, engine.params.ORDER_A_ENCODED_BYTES, b0, engine.params.ORDER_A_ENCODED_BYTES, engine.params.NWORDS_ORDER);
        engine.fpx.decode_to_digits(CompressedPKB, 2 * engine.params.ORDER_A_ENCODED_BYTES, a1, engine.params.ORDER_A_ENCODED_BYTES, engine.params.NWORDS_ORDER);
        engine.fpx.decode_to_digits(CompressedPKB, 3 * engine.params.ORDER_A_ENCODED_BYTES, b1, engine.params.ORDER_A_ENCODED_BYTES, engine.params.NWORDS_ORDER);

        if ((a0[0] & 1) == 1)
        {
            engine.fpx.multiply(SKin, b1, tmp1, engine.params.NWORDS_ORDER);
            engine.fpx.mp_add(tmp1, b0, tmp1, engine.params.NWORDS_ORDER);
            tmp1[engine.params.NWORDS_ORDER - 1] &= mask;
            engine.fpx.multiply(SKin, a1, tmp2, engine.params.NWORDS_ORDER);
            engine.fpx.mp_add(tmp2, a0, tmp2, engine.params.NWORDS_ORDER);
            tmp2[engine.params.NWORDS_ORDER - 1] &= mask;
            engine.fpx.inv_mod_orderA(tmp2, inv);
            engine.fpx.multiply(tmp1, inv, scal, engine.params.NWORDS_ORDER);
            scal[engine.params.NWORDS_ORDER - 1] &= mask;
            Ladder3pt_dual(Rs, scal, engine.params.ALICE, R, A24);
        }
        else
        {
            engine.fpx.multiply(SKin, a1, tmp1, engine.params.NWORDS_ORDER);
            engine.fpx.mp_add(tmp1, a0, tmp1, engine.params.NWORDS_ORDER);
            tmp1[engine.params.NWORDS_ORDER - 1] &= (long)mask;
            engine.fpx.multiply(SKin, b1, tmp2, engine.params.NWORDS_ORDER);
            engine.fpx.mp_add(tmp2, b0, tmp2, engine.params.NWORDS_ORDER);
            tmp2[engine.params.NWORDS_ORDER - 1] &= (long)mask;
            engine.fpx.inv_mod_orderA(tmp2, inv);
            engine.fpx.multiply(inv, tmp1, scal, engine.params.NWORDS_ORDER);
            scal[engine.params.NWORDS_ORDER - 1] &= (long)mask;
            engine.isogeny.swap_points(Rs[0], Rs[1], -1L);
            Ladder3pt_dual(Rs, scal, engine.params.ALICE, R, A24);
        }

        engine.fpx.fp2div2(A, Adiv2);
        engine.isogeny.xTPLe_fast(R, R, Adiv2, engine.params.OBOB_EXPON);

        engine.fpx.fp2_encode(R.X, tphiBKA_t, tphiBKA_tOffset);
        engine.fpx.fp2_encode(R.Z, tphiBKA_t, tphiBKA_tOffset + engine.params.FP2_ENCODED_BYTES);
        engine.fpx.encode_to_bytes(inv, tphiBKA_t, tphiBKA_tOffset + 2 * engine.params.FP2_ENCODED_BYTES, engine.params.ORDER_A_ENCODED_BYTES);
    }

    // Bob's PK compression -- SIKE protocol
    protected void Compress_PKB_dual_extended(long[] d0, long[] c0, long[] d1, long[] c1, long[][] A, byte[] qnr, byte[] ind, byte[] CompressedPKB)
    {
        long mask = -1L;
        long[] tmp = new long[2 * engine.params.NWORDS_ORDER],
            D = new long[2 * engine.params.NWORDS_ORDER], Dinv = new long[2 * engine.params.NWORDS_ORDER];

        mask >>>= (engine.params.MAXBITS_ORDER - engine.params.OALICE_BITS);

        engine.fpx.multiply(c0, d1, tmp, engine.params.NWORDS_ORDER);
        engine.fpx.multiply(c1, d0, D, engine.params.NWORDS_ORDER);
        engine.fpx.Montgomery_neg(D, engine.params.Alice_order);
        engine.fpx.mp_add(tmp, D, D, engine.params.NWORDS_ORDER);
        D[engine.params.NWORDS_ORDER - 1] &= (long)mask;
        engine.fpx.inv_mod_orderA(D, Dinv);
        engine.fpx.multiply(d1, Dinv, tmp, engine.params.NWORDS_ORDER); // a0' = 3^n * d1 / D
        tmp[engine.params.NWORDS_ORDER - 1] &= mask;
        engine.fpx.encode_to_bytes(tmp, CompressedPKB, 0, engine.params.ORDER_A_ENCODED_BYTES);

        engine.fpx.Montgomery_neg(d0, engine.params.Alice_order);
        engine.fpx.multiply(d0, Dinv, tmp, engine.params.NWORDS_ORDER); // b0' = 3^n * (- d0 / D)
        tmp[engine.params.NWORDS_ORDER - 1] &= (long)mask;
        engine.fpx.encode_to_bytes(tmp, CompressedPKB, engine.params.ORDER_A_ENCODED_BYTES, engine.params.ORDER_A_ENCODED_BYTES);

        engine.fpx.Montgomery_neg(c1, engine.params.Alice_order);
        engine.fpx.multiply(c1, Dinv, tmp, engine.params.NWORDS_ORDER); // a1' = 3^n * (- c1 / D)
        tmp[engine.params.NWORDS_ORDER - 1] &= (long)mask;
        engine.fpx.encode_to_bytes(tmp, CompressedPKB, 2 * engine.params.ORDER_A_ENCODED_BYTES, engine.params.ORDER_A_ENCODED_BYTES);

        engine.fpx.multiply(c0, Dinv, tmp, engine.params.NWORDS_ORDER); // b1' = 3^n * (c0 / D)
        tmp[engine.params.NWORDS_ORDER - 1] &= (long)mask;
        engine.fpx.encode_to_bytes(tmp, CompressedPKB, 3 * engine.params.ORDER_A_ENCODED_BYTES, engine.params.ORDER_A_ENCODED_BYTES);

        engine.fpx.fp2_encode(A, CompressedPKB, 4 * engine.params.ORDER_A_ENCODED_BYTES);
        CompressedPKB[4 * engine.params.ORDER_A_ENCODED_BYTES + engine.params.FP2_ENCODED_BYTES] = qnr[0];
        CompressedPKB[4 * engine.params.ORDER_A_ENCODED_BYTES + engine.params.FP2_ENCODED_BYTES + 1] = ind[0];
    }

    // Bob's PK decompression -- SIDH protocol
    protected void PKBDecompression(byte[] SecretKeyA, int SecretKeyAOffset, byte[] CompressedPKB, PointProj R, long[][] A)
    {
        long mask = -1L;
        int bit, qnr, ind;
        long[][] A24 = new long[2][engine.params.NWORDS_FIELD];
        long[] tmp1 = new long[2 * engine.params.NWORDS_ORDER],
            tmp2 = new long[2 * engine.params.NWORDS_ORDER],
            vone = new long[2 * engine.params.NWORDS_ORDER],
            SKin = new long[engine.params.NWORDS_ORDER],
            comp_temp = new long[engine.params.NWORDS_ORDER];
        PointProj[] Rs = new PointProj[3];

        mask >>>= (engine.params.MAXBITS_ORDER - engine.params.OALICE_BITS);
        vone[0] = 1;

        engine.fpx.fp2_decode(CompressedPKB, A, 3 * engine.params.ORDER_A_ENCODED_BYTES);
        bit = CompressedPKB[3 * engine.params.ORDER_A_ENCODED_BYTES + engine.params.FP2_ENCODED_BYTES] >>> 7;
        qnr = CompressedPKB[3 * engine.params.ORDER_A_ENCODED_BYTES + engine.params.FP2_ENCODED_BYTES] & 0x1;
        ind = CompressedPKB[3 * engine.params.ORDER_A_ENCODED_BYTES + engine.params.FP2_ENCODED_BYTES + 1];

        // Rebuild the basis 
        BuildEntangledXonly_Decomp(A, Rs, qnr, ind);
        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, Rs[0].Z[0]);
        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, Rs[1].Z[0]);

        engine.fpx.fpaddPRIME(A[0], engine.params.Montgomery_one, A24[0]);
        engine.fpx.fpcopy(A[1], 0, A24[1]);
        engine.fpx.fpaddPRIME(A24[0], engine.params.Montgomery_one, A24[0]);
        engine.fpx.fp2div2(A24, A24);
        engine.fpx.fp2div2(A24, A24);

        engine.fpx.decode_to_digits(SecretKeyA, SecretKeyAOffset, SKin, engine.params.SECRETKEY_A_BYTES, engine.params.NWORDS_ORDER);
        engine.isogeny.swap_points(Rs[0], Rs[1], 0 - (long)bit);
        if (bit == 0)
        {
            engine.fpx.decode_to_digits(CompressedPKB, engine.params.ORDER_A_ENCODED_BYTES, comp_temp, engine.params.ORDER_A_ENCODED_BYTES, engine.params.NWORDS_ORDER);
            engine.fpx.multiply(SKin, comp_temp, tmp1, engine.params.NWORDS_ORDER);
            engine.fpx.mp_add(tmp1, vone, tmp1, engine.params.NWORDS_ORDER);
            tmp1[engine.params.NWORDS_ORDER - 1] &= (long)mask;
            engine.fpx.inv_mod_orderA(tmp1, tmp2);
            engine.fpx.decode_to_digits(CompressedPKB, 2 * engine.params.ORDER_A_ENCODED_BYTES, comp_temp, engine.params.ORDER_A_ENCODED_BYTES, engine.params.NWORDS_ORDER);
            engine.fpx.multiply(SKin, comp_temp, tmp1, engine.params.NWORDS_ORDER);
            engine.fpx.decode_to_digits(CompressedPKB, 0, comp_temp, engine.params.ORDER_A_ENCODED_BYTES, engine.params.NWORDS_ORDER);
            engine.fpx.mp_add(comp_temp, tmp1, tmp1, engine.params.NWORDS_ORDER);
            engine.fpx.multiply(tmp1, tmp2, vone, engine.params.NWORDS_ORDER);
            vone[engine.params.NWORDS_ORDER - 1] &= mask;
            Ladder3pt_dual(Rs, vone, engine.params.ALICE, R, A24);
        }
        else
        {
            engine.fpx.decode_to_digits(CompressedPKB, 2 * engine.params.ORDER_A_ENCODED_BYTES, comp_temp, engine.params.ORDER_A_ENCODED_BYTES, engine.params.NWORDS_ORDER);
            engine.fpx.multiply(SKin, comp_temp, tmp1, engine.params.NWORDS_ORDER);
            engine.fpx.mp_add(tmp1, vone, tmp1, engine.params.NWORDS_ORDER);
            tmp1[engine.params.NWORDS_ORDER - 1] &= mask;
            engine.fpx.inv_mod_orderA(tmp1, tmp2);
            engine.fpx.decode_to_digits(CompressedPKB, engine.params.ORDER_A_ENCODED_BYTES, comp_temp, engine.params.ORDER_A_ENCODED_BYTES, engine.params.NWORDS_ORDER);
            engine.fpx.multiply(SKin, comp_temp, tmp1, engine.params.NWORDS_ORDER);
            engine.fpx.decode_to_digits(CompressedPKB, 0, comp_temp, engine.params.ORDER_A_ENCODED_BYTES, engine.params.NWORDS_ORDER);
            engine.fpx.mp_add(comp_temp, tmp1, tmp1, engine.params.NWORDS_ORDER);
            engine.fpx.multiply(tmp1, tmp2, vone, engine.params.NWORDS_ORDER);
            vone[engine.params.NWORDS_ORDER - 1] &= mask;
            Ladder3pt_dual(Rs, vone, engine.params.ALICE, R, A24);
        }
        engine.fpx.fp2div2(A, A24);
        engine.isogeny.xTPLe_fast(R, R, A24, engine.params.OBOB_EXPON);
    }

    // Bob's PK compression -- SIDH protocol
    protected void Compress_PKB_dual(long[] d0, long[] c0, long[] d1, long[] c1, long[][] A, byte qnr[], byte ind[], byte[] CompressedPKB)
    {
        long[] tmp = new long[2 * engine.params.NWORDS_ORDER],
            inv = new long[engine.params.NWORDS_ORDER];
        if ((d1[0] & 1) == 1)
        {  // Storing [-d0*d1^-1 = b1*a0^-1, -c1*d1^-1 = a1*a0^-1, c0*d1^-1 = b0*a0^-1] and setting bit384 to 0
            engine.fpx.inv_mod_orderA(d1, inv);
            engine.fpx.Montgomery_neg(d0, engine.params.Alice_order);
            engine.fpx.multiply(d0, inv, tmp, engine.params.NWORDS_ORDER);
            engine.fpx.encode_to_bytes(tmp, CompressedPKB, 0, engine.params.ORDER_A_ENCODED_BYTES);
            CompressedPKB[engine.params.ORDER_A_ENCODED_BYTES - 1] &= engine.params.MASK_ALICE;
            engine.fpx.Montgomery_neg(c1, engine.params.Alice_order);
            engine.fpx.multiply(c1, inv, tmp, engine.params.NWORDS_ORDER);
            engine.fpx.encode_to_bytes(tmp, CompressedPKB, engine.params.ORDER_A_ENCODED_BYTES, engine.params.ORDER_A_ENCODED_BYTES);
            CompressedPKB[2 * engine.params.ORDER_A_ENCODED_BYTES - 1] &= engine.params.MASK_ALICE;
            engine.fpx.multiply(c0, inv, tmp, engine.params.NWORDS_ORDER);
            engine.fpx.encode_to_bytes(tmp, CompressedPKB, 2 * engine.params.ORDER_A_ENCODED_BYTES, engine.params.ORDER_A_ENCODED_BYTES);
            CompressedPKB[3 * engine.params.ORDER_A_ENCODED_BYTES - 1] &= engine.params.MASK_ALICE;
            CompressedPKB[3 * engine.params.ORDER_A_ENCODED_BYTES + engine.params.FP2_ENCODED_BYTES] = 0x00;
        }
        else
        {  // Storing [ -d1*d0^-1 = b1*b0inv, c1*d0^-1 = a1*b0inv, -c0*d0^-1 = a0*b0inv] and setting bit384 to 1
            engine.fpx.inv_mod_orderA(d0, inv);
            engine.fpx.Montgomery_neg(d1, engine.params.Alice_order);
            engine.fpx.multiply(d1, inv, tmp, engine.params.NWORDS_ORDER);
            engine.fpx.encode_to_bytes(tmp, CompressedPKB, 0, engine.params.ORDER_A_ENCODED_BYTES);
            CompressedPKB[engine.params.ORDER_A_ENCODED_BYTES - 1] &= engine.params.MASK_ALICE;
            engine.fpx.multiply(c1, inv, tmp, engine.params.NWORDS_ORDER);
            engine.fpx.encode_to_bytes(tmp, CompressedPKB, engine.params.ORDER_A_ENCODED_BYTES, engine.params.ORDER_A_ENCODED_BYTES);
            CompressedPKB[2 * engine.params.ORDER_A_ENCODED_BYTES - 1] &= engine.params.MASK_ALICE;
            engine.fpx.Montgomery_neg(c0, engine.params.Alice_order);
            engine.fpx.multiply(c0, inv, tmp, engine.params.NWORDS_ORDER);
            engine.fpx.encode_to_bytes(tmp, CompressedPKB, 2 * engine.params.ORDER_A_ENCODED_BYTES, engine.params.ORDER_A_ENCODED_BYTES);
            CompressedPKB[3 * engine.params.ORDER_A_ENCODED_BYTES - 1] &= engine.params.MASK_ALICE;
            CompressedPKB[3 * engine.params.ORDER_A_ENCODED_BYTES + engine.params.FP2_ENCODED_BYTES] = (byte)0x80;
        }

        engine.fpx.fp2_encode(A, CompressedPKB, 3 * engine.params.ORDER_A_ENCODED_BYTES);
        CompressedPKB[3 * engine.params.ORDER_A_ENCODED_BYTES + engine.params.FP2_ENCODED_BYTES] |= qnr[0];
        CompressedPKB[3 * engine.params.ORDER_A_ENCODED_BYTES + engine.params.FP2_ENCODED_BYTES + 1] = ind[0];
        CompressedPKB[3 * engine.params.ORDER_A_ENCODED_BYTES + engine.params.FP2_ENCODED_BYTES + 2] = 0;
    }

    // Bob's ephemeral public key generation using compression -- SIKE protocol
    protected int EphemeralKeyGeneration_B_extended(byte[] PrivateKeyB, byte[] CompressedPKB, int sike)
    {
        byte[] qnr = new byte[1], ind = new byte[1];
        int[] D = new int[engine.params.DLEN_2];
        long[] c0 = new long[engine.params.NWORDS_ORDER],
            d0 = new long[engine.params.NWORDS_ORDER],
            c1 = new long[engine.params.NWORDS_ORDER],
            d1 = new long[engine.params.NWORDS_ORDER];
        long[][][][] Ds = new long[engine.params.MAX_Bob][2][2][engine.params.NWORDS_FIELD];
        long[][][] f = new long[4][2][engine.params.NWORDS_FIELD];
        long[][] A = new long[2][engine.params.NWORDS_FIELD];

        PointProjFull[] Rs = new PointProjFull[2];
        Rs[0] = new PointProjFull(engine.params.NWORDS_FIELD);
        Rs[1] = new PointProjFull(engine.params.NWORDS_FIELD);

        PointProj Pw = new PointProj(engine.params.NWORDS_FIELD),
            Qw = new PointProj(engine.params.NWORDS_FIELD);

        FullIsogeny_B_dual(PrivateKeyB, Ds, A);
        BuildOrdinary2nBasis_dual(A, Ds, Rs, qnr, ind);  // Generate a basis in E_A and pulls it back to E_A6. Rs[0] and Rs[1] affinized.

        // Maps from y^2 = x^3 + 6x^2 + x into y^2 = x^3 -11x + 14
        engine.fpx.fpaddPRIME(engine.params.Montgomery_one, Rs[0].X[0], Rs[0].X[0]);
        engine.fpx.fpaddPRIME(engine.params.Montgomery_one, Rs[0].X[0], Rs[0].X[0]);  // Weierstrass form
        engine.fpx.fpaddPRIME(engine.params.Montgomery_one, Rs[1].X[0], Rs[1].X[0]);
        engine.fpx.fpaddPRIME(engine.params.Montgomery_one, Rs[1].X[0], Rs[1].X[0]);  // Weierstrass form

        engine.fpx.fpcopy(engine.params.A_basis_zero, 0 * engine.params.NWORDS_FIELD, Pw.X[0]);
        engine.fpx.fpcopy(engine.params.A_basis_zero, 1 * engine.params.NWORDS_FIELD, Pw.X[1]);
        engine.fpx.fpcopy(engine.params.A_basis_zero, 2 * engine.params.NWORDS_FIELD, Pw.Z[0]);//y
        engine.fpx.fpcopy(engine.params.A_basis_zero, 3 * engine.params.NWORDS_FIELD, Pw.Z[1]);//y
        engine.fpx.fpcopy(engine.params.A_basis_zero, 4 * engine.params.NWORDS_FIELD, Qw.X[0]);
        engine.fpx.fpcopy(engine.params.A_basis_zero, 5 * engine.params.NWORDS_FIELD, Qw.X[1]);
        engine.fpx.fpcopy(engine.params.A_basis_zero, 6 * engine.params.NWORDS_FIELD, Qw.Z[0]);//y
        engine.fpx.fpcopy(engine.params.A_basis_zero, 7 * engine.params.NWORDS_FIELD, Qw.Z[1]);//y

        Tate2_pairings(Pw, Qw, Rs, f);
        engine.fpx.fp2correction(f[0]);
        engine.fpx.fp2correction(f[1]);
        engine.fpx.fp2correction(f[2]);
        engine.fpx.fp2correction(f[3]);
        Dlogs2_dual(f, D, d0, c0, d1, c1);

        if (sike == 1)
        {
            Compress_PKB_dual_extended(d0, c0, d1, c1, A, qnr, ind, CompressedPKB);
        }
        else
        {
            Compress_PKB_dual(d0, c0, d1, c1, A, qnr, ind, CompressedPKB);
        }

        return 0;
    }

    // Bob's ephemeral public key generation using compression -- SIDH protocol
    protected int EphemeralKeyGeneration_B(byte[] PrivateKeyB, byte[] CompressedPKB)
    {
        return EphemeralKeyGeneration_B_extended(PrivateKeyB, CompressedPKB, 0);
    }

    // Alice's ephemeral shared secret computation using compression -- SIKE protocol
    protected int EphemeralSecretAgreement_A_extended(byte[] PrivateKeyA, int PrivateKeyAOffset, byte[] PKB, byte[] SharedSecretA, int sike)
    {
        int i, ii = 0, row, m, index = 0, npts = 0;
        int[] pts_index = new int[engine.params.MAX_INT_POINTS_ALICE];
        long[][] A24plus = new long[2][engine.params.NWORDS_FIELD],
            C24 = new long[2][engine.params.NWORDS_FIELD];

        PointProj R = new PointProj(engine.params.NWORDS_FIELD);
        PointProj[] pts = new PointProj[engine.params.MAX_INT_POINTS_ALICE];
        long[][] jinv = new long[2][engine.params.NWORDS_FIELD],
            A = new long[2][engine.params.NWORDS_FIELD],
            param_A = new long[2][engine.params.NWORDS_FIELD];
        long[][][] coeff = new long[5][2][engine.params.NWORDS_FIELD];


        if (sike == 1)
        {
            PKBDecompression_extended(PrivateKeyA, PrivateKeyAOffset, PKB, R, param_A, SharedSecretA, engine.params.FP2_ENCODED_BYTES);
        }
        else
        {
            PKBDecompression(PrivateKeyA, PrivateKeyAOffset, PKB, R, param_A);
        }

        engine.fpx.fp2copy(param_A, A);
        engine.fpx.fpaddPRIME(engine.params.Montgomery_one, engine.params.Montgomery_one, C24[0]);
        engine.fpx.fp2add(A, C24, A24plus);
        engine.fpx.fpaddPRIME(C24[0], C24[0], C24[0]);

        if (engine.params.OALICE_BITS % 2 == 1)
        {
            PointProj S = new PointProj(engine.params.NWORDS_FIELD);

            engine.isogeny.xDBLe(R, S, A24plus, C24, (engine.params.OALICE_BITS - 1));
            engine.isogeny.get_2_isog(S, A24plus, C24);
            engine.isogeny.eval_2_isog(R, S);
        }

        // Traverse tree
        index = 0;
        for (row = 1; row < engine.params.MAX_Alice; row++)
        {
            while (index < engine.params.MAX_Alice - row)
            {
                pts[npts] = new PointProj(engine.params.NWORDS_FIELD);
                engine.fpx.fp2copy(R.X, pts[npts].X);
                engine.fpx.fp2copy(R.Z, pts[npts].Z);
                pts_index[npts++] = index;
                m = engine.params.strat_Alice[ii++];
                engine.isogeny.xDBLe(R, R, A24plus, C24, (int)(2 * m));
                index += m;
            }
            engine.isogeny.get_4_isog(R, A24plus, C24, coeff);

            for (i = 0; i < npts; i++)
            {
                engine.isogeny.eval_4_isog(pts[i], coeff);
            }

            engine.fpx.fp2copy(pts[npts - 1].X, R.X);
            engine.fpx.fp2copy(pts[npts - 1].Z, R.Z);
            index = pts_index[npts - 1];
            npts -= 1;
        }

        engine.isogeny.get_4_isog(R, A24plus, C24, coeff);
        engine.fpx.fp2add(A24plus, A24plus, A24plus);
        engine.fpx.fp2sub(A24plus, C24, A24plus);
        engine.fpx.fp2add(A24plus, A24plus, A24plus);
        engine.isogeny.j_inv(A24plus, C24, jinv);
        engine.fpx.fp2_encode(jinv, SharedSecretA, 0);    // Format shared secret

        return 0;
    }

    // Alice's ephemeral shared secret computation using compression -- SIDH protocol
    // It produces a shared secret key SharedSecretA using her secret key PrivateKeyA and Bob's decompressed data point_R and param_A
    // Inputs: Alice's PrivateKeyA is an even integer in the range [2, oA-2], where oA = 2^engine.params.OALICE_BITS.
    //         Bob's decompressed data consists of point_R in (X:Z) coordinates and the curve parameter param_A in GF(p^2).
    // Output: a shared secret SharedSecretA that consists of one element in GF(p^2).
    int EphemeralSecretAgreement_A(byte[] PrivateKeyA, int PrivateKeyAOffset, byte[] PKB, byte[] SharedSecretA)
    {
        return EphemeralSecretAgreement_A_extended(PrivateKeyA, PrivateKeyAOffset, PKB, SharedSecretA, 0);
    }


    protected byte validate_ciphertext(byte[] ephemeralsk_, byte[] CompressedPKB, byte[] xKA, int xKAOffset, byte[] tphiBKA_t, int tphiBKA_tOffset)
    { // If ct validation passes returns 0, otherwise returns -1.
        PointProj[] phis = new PointProj[3],
            pts = new PointProj[engine.params.MAX_INT_POINTS_BOB];

        phis[0] = new PointProj(engine.params.NWORDS_FIELD);
        phis[1] = new PointProj(engine.params.NWORDS_FIELD);
        phis[2] = new PointProj(engine.params.NWORDS_FIELD);

        PointProj R = new PointProj(engine.params.NWORDS_FIELD),
            S = new PointProj(engine.params.NWORDS_FIELD);

        long[][] XPB = new long[2][engine.params.NWORDS_FIELD],
            XQB = new long[2][engine.params.NWORDS_FIELD],
            XRB = new long[2][engine.params.NWORDS_FIELD],
            A24plus = new long[2][engine.params.NWORDS_FIELD],
            A24minus = new long[2][engine.params.NWORDS_FIELD],
            A = new long[2][engine.params.NWORDS_FIELD],
            comp1 = new long[2][engine.params.NWORDS_FIELD],
            comp2 = new long[2][engine.params.NWORDS_FIELD],
            one = new long[2][engine.params.NWORDS_FIELD];
        long[][][] coeff = new long[3][2][engine.params.NWORDS_FIELD];

        int i, row, m, index = 0, npts = 0, ii = 0;
        int[] pts_index = new int[engine.params.MAX_INT_POINTS_BOB];
        long[] temp = new long[engine.params.NWORDS_ORDER],
            sk = new long[engine.params.NWORDS_ORDER];

        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, one[0]);

        // Initialize basis points
        init_basis(engine.params.B_gen, XPB, XQB, XRB);

        engine.fpx.fp2_decode(xKA, phis[0].X, xKAOffset);
        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, phis[0].Z[0]); // phi[0] <- PA + skA*QA

        // Initialize constants: A24minus = A-2C, A24plus = A+2C, where A=6, C=1
        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, A24plus[0]);
        engine.fpx.fp2add(A24plus, A24plus, A24plus);
        engine.fpx.fp2add(A24plus, A24plus, A24minus);  // A24minus = 4
        engine.fpx.fp2add(A24plus, A24minus, A);        // A = 6
        engine.fpx.fp2add(A24minus, A24minus, A24plus); // A24plus = 8

        // Retrieve kernel point
        engine.fpx.decode_to_digits(ephemeralsk_, 0, sk, engine.params.SECRETKEY_B_BYTES, engine.params.NWORDS_ORDER);
        engine.isogeny.LADDER3PT(XPB, XQB, XRB, sk, engine.params.BOB, R, A);

        // Traverse tree
        index = 0;
        for (row = 1; row < engine.params.MAX_Bob; row++)
        {
            while (index < engine.params.MAX_Bob - row)
            {
                pts[npts] = new PointProj(engine.params.NWORDS_FIELD);
                engine.fpx.fp2copy(R.X, pts[npts].X);
                engine.fpx.fp2copy(R.Z, pts[npts].Z);
                pts_index[npts++] = index;
                m = engine.params.strat_Bob[ii++];
                engine.isogeny.xTPLe(R, R, A24minus, A24plus, (int)m);
                index += m;
            }
            engine.isogeny.get_3_isog(R, A24minus, A24plus, coeff);
            for (i = 0; i < npts; i++)
            {
                engine.isogeny.eval_3_isog(pts[i], coeff);
            }
            engine.isogeny.eval_3_isog(phis[0], coeff);

            engine.fpx.fp2copy(pts[npts - 1].X, R.X);
            engine.fpx.fp2copy(pts[npts - 1].Z, R.Z);
            index = pts_index[npts - 1];
            npts -= 1;
        }
        engine.isogeny.get_3_isog(R, A24minus, A24plus, coeff);
        engine.isogeny.eval_3_isog(phis[0], coeff);  // phis[0] <- phiB(PA + skA*QA)

        engine.fpx.fp2_decode(CompressedPKB, A, 4 * engine.params.ORDER_A_ENCODED_BYTES);

        // Single equation check: t*(phiP + skA*phiQ) =? t*3^n*((a0+skA*a1)*S1 + (b0+skA*b1)*S2) for t in {(a0+skA*a1)^-1, (b0+skA*b1)^-1}

        engine.fpx.fp2_decode(tphiBKA_t, S.X, tphiBKA_tOffset);
        engine.fpx.fp2_decode(tphiBKA_t, S.Z, tphiBKA_tOffset + engine.params.FP2_ENCODED_BYTES);  // Recover t*3^n*((a0+skA*a1)*S1 + (b0+skA*b1)*S2)
        engine.fpx.decode_to_digits(tphiBKA_t, tphiBKA_tOffset + 2 * engine.params.FP2_ENCODED_BYTES, temp, engine.params.ORDER_A_ENCODED_BYTES, engine.params.NWORDS_ORDER);
        engine.isogeny.Ladder(phis[0], temp, A, engine.params.OALICE_BITS, R);         // t*(phiP + skA*phiQ)

        engine.fpx.fp2mul_mont(R.X, S.Z, comp1);
        engine.fpx.fp2mul_mont(R.Z, S.X, comp2);
        return (engine.fpx.cmp_f2elm(comp1, comp2));
    }


    /// DLOG

    // Computes the discrete log of input r = g^d where g = e(P,Q)^ell^e, and P,Q are torsion generators in the initial curve
    // Return the integer d
    void solve_dlog(long[][] r, int[] D, long[] d, int ell)
    {
        if (ell == 2)
        {
            if (engine.params.OALICE_BITS % engine.params.W_2 == 0)
            {
                Traverse_w_div_e_fullsigned(r, 0, 0, engine.params.PLEN_2 - 1, engine.params.ph2_path,
                    engine.params.ph2_T, D, engine.params.DLEN_2, engine.params.ELL2_W, engine.params.W_2);
            }
            else
            {
                Traverse_w_notdiv_e_fullsigned(r, 0, 0, engine.params.PLEN_2 - 1, engine.params.ph2_path,
                    engine.params.ph2_T1, engine.params.ph2_T2, D, engine.params.DLEN_2, ell, engine.params.ELL2_W,
                    engine.params.ELL2_EMODW, engine.params.W_2, engine.params.OALICE_BITS);
            }
            from_base(D, d, engine.params.DLEN_2, engine.params.ELL2_W);
        }
        else if (ell == 3)
        {
            if (engine.params.OBOB_EXPON % engine.params.W_3 == 0)
            {
                Traverse_w_div_e_fullsigned(r, 0, 0, engine.params.PLEN_3 - 1, engine.params.ph3_path,
                    engine.params.ph3_T, D, engine.params.DLEN_3, engine.params.ELL3_W, engine.params.W_3);
            }
            else
            {
                Traverse_w_notdiv_e_fullsigned(r, 0, 0, engine.params.PLEN_3 - 1, engine.params.ph3_path,
                    engine.params.ph3_T1, engine.params.ph3_T2, D, engine.params.DLEN_3, ell, engine.params.ELL3_W,
                    engine.params.ELL3_EMODW, engine.params.W_3, engine.params.OBOB_EXPON);
            }
            from_base(D, d, engine.params.DLEN_3, engine.params.ELL3_W);
        }
    }

    // Convert a number in base "base" with signed digits: (D[k-1]D[k-2]...D[1]D[0])_base < 2^(NWORDS_ORDER*RADIX) into decimal
    // Output: r = D[k-1]*base^(k-1) + ... + D[1]*base + D[0]
    private void from_base(int[] D, long[] r, int Dlen, int base)
    {
        long[] ell = new long[engine.params.NWORDS_ORDER],
            digit = new long[engine.params.NWORDS_ORDER],
            temp = new long[engine.params.NWORDS_ORDER];
        int ellw;

        ell[0] = base;
        if (D[Dlen - 1] < 0)
        {
            digit[0] = (((int)-D[Dlen - 1]) * ell[0]);
            if ((base & 1) == 0)
            {
                engine.fpx.Montgomery_neg(digit, engine.params.Alice_order);
                engine.fpx.copy_words(digit, r, engine.params.NWORDS_ORDER);
            }
            else
            {
                engine.fpx.mp_sub(engine.params.Bob_order, digit, r, engine.params.NWORDS_ORDER);
            }
        }
        else
        {
            r[0] = (D[Dlen - 1] * ell[0]);
        }

        for (int i = Dlen - 2; i >= 1; i--)
        {
            ellw = base;
            Arrays.fill(digit, 0);
            if (D[i] < 0)
            {
                digit[0] = (-D[i]);
                if ((base & 1) == 0)
                {
                    engine.fpx.Montgomery_neg(digit, engine.params.Alice_order);
                }
                else
                {
                    engine.fpx.mp_sub(engine.params.Bob_order, digit, digit, engine.params.NWORDS_ORDER);
                }
            }
            else
            {
                digit[0] = D[i];
            }
            engine.fpx.mp_add(r, digit, r, engine.params.NWORDS_ORDER);
            if ((base & 1) != 0)
            {
                if (!engine.fpx.is_orderelm_lt(r, engine.params.Bob_order))
                {
                    engine.fpx.mp_sub(r, engine.params.Bob_order, r, engine.params.NWORDS_ORDER);
                }
            }

            if ((base & 1) == 0)
            {
                while (ellw > 1)
                {
                    engine.fpx.mp_add(r, r, r, engine.params.NWORDS_ORDER);
                    ellw /= 2;
                }
            }
            else
            {
                while (ellw > 1)
                {
                    Arrays.fill(temp, 0);
                    engine.fpx.mp_add(r, r, temp, engine.params.NWORDS_ORDER);
                    if (!engine.fpx.is_orderelm_lt(temp, engine.params.Bob_order))
                    {
                        engine.fpx.mp_sub(temp, engine.params.Bob_order, temp, engine.params.NWORDS_ORDER);
                    }

                    engine.fpx.mp_add(r, temp, r, engine.params.NWORDS_ORDER);

                    if (!engine.fpx.is_orderelm_lt(r, engine.params.Bob_order))
                    {
                        engine.fpx.mp_sub(r, engine.params.Bob_order, r, engine.params.NWORDS_ORDER);
                    }
                    ellw /= 3;
                }
            }
        }
        Arrays.fill(digit, 0);
        if (D[0] < 0)
        {
            digit[0] = (-D[0]);
            if ((base & 1) == 0)
            {
                engine.fpx.Montgomery_neg(digit, engine.params.Alice_order);
            }
            else
            {
                engine.fpx.mp_sub(engine.params.Bob_order, digit, digit, engine.params.NWORDS_ORDER);
            }
        }
        else
        {
            digit[0] = D[0];
        }
        engine.fpx.mp_add(r, digit, r, engine.params.NWORDS_ORDER);
        if ((base & 1) != 0)
        {
            if (!engine.fpx.is_orderelm_lt(r, engine.params.Bob_order))
            {
                engine.fpx.mp_sub(r, engine.params.Bob_order, r, engine.params.NWORDS_ORDER);
            }
        }
    }


    // Traverse a Pohlig-Hellman optimal strategy to solve a discrete log in a group of order ell^e
    // Leaves are used to recover the digits which are numbers from 0 to ell^w-1 except by the last leaf that gives a digit between 0 and ell^(e mod w)
    // Assume w does not divide the exponent e
    void Traverse_w_notdiv_e_fullsigned(long[][] r, int j, int k, int z, int[] P, long[] CT1, long[] CT2,
                                        int[] D, int Dlen, int ell, int ellw, int ell_emodw, int w, int e)
    {
        long[][] rp = new long[2][engine.params.NWORDS_FIELD],
            alpha = new long[2][engine.params.NWORDS_FIELD];


        if (z > 1)
        {
            int t = P[z], goleft;
            engine.fpx.fp2copy(r, rp);
            goleft = (j > 0) ? w * (z - t) : (e % w) + w * (z - t - 1);
            for (int i = 0; i < goleft; i++)
            {
                if ((ell & 1) == 0)
                {
                    engine.fpx.sqr_Fp2_cycl(rp, engine.params.Montgomery_one);
                }
                else
                {
                    engine.fpx.cube_Fp2_cycl(rp, engine.params.Montgomery_one);
                }

            }

            Traverse_w_notdiv_e_fullsigned(rp, j + (z - t), k, t, P, CT1, CT2, D, Dlen, ell, ellw, ell_emodw, w, e);

            engine.fpx.fp2copy(r, rp);
            for (int h = k; h < k + t; h++)
            {
                if (D[h] != 0)
                {
                    if (j > 0)
                    {
                        if (D[h] < 0)
                        {
                            engine.fpx.fp2copy(CT2, engine.params.NWORDS_FIELD * (2 * (j + h) * (ellw / 2) + 2 * (-D[h] - 1)), alpha);
                            engine.fpx.fpnegPRIME(alpha[1]);
                            engine.fpx.fp2mul_mont(rp, alpha, rp);
                        }
                        else
                        {
                            engine.fpx.fp2mul_mont(rp, CT2, engine.params.NWORDS_FIELD * (2 * ((j + h) * (ellw / 2) + (D[h] - 1))), rp);
                        }
                    }
                    else
                    {
                        if (D[h] < 0)
                        {
                            engine.fpx.fp2copy(CT1, engine.params.NWORDS_FIELD * (2 * ((j + h) * (ellw / 2) + (-D[h] - 1))), alpha);
                            engine.fpx.fpnegPRIME(alpha[1]);
                            engine.fpx.fp2mul_mont(rp, alpha, rp);
                        }
                        else
                        {
                            engine.fpx.fp2mul_mont(rp, CT1, engine.params.NWORDS_FIELD * (2 * ((j + h) * (ellw / 2) + (D[h] - 1))), rp);
                        }
                    }
                }
            }

            Traverse_w_notdiv_e_fullsigned(rp, j, k + t, z - t, P, CT1, CT2, D, Dlen, ell, ellw, ell_emodw, w, e);
        }
        else
        {
            engine.fpx.fp2copy(r, rp);
            engine.fpx.fp2correction(rp);


            if (engine.fpx.is_felm_zero(rp[1]) && Fpx.subarrayEquals(rp[0], engine.params.Montgomery_one, engine.params.NWORDS_FIELD))
            {
                D[k] = 0;
            }
            else
            {

                if (!(j == 0 && k == Dlen - 1))
                {

                    for (int t = 1; t <= (ellw / 2); t++)
                    {
                        if (Fpx.subarrayEquals(rp, CT2, engine.params.NWORDS_FIELD * (2 * (ellw / 2) * (Dlen - 1) + 2 * (t - 1)), 2 * engine.params.NWORDS_FIELD))
                        {
                            D[k] = -t;
                            break;
                        }
                        else
                        {
                            engine.fpx.fp2copy(CT2, engine.params.NWORDS_FIELD * (2 * ((ellw / 2) * (Dlen - 1) + (t - 1))), alpha);
                            engine.fpx.fpnegPRIME(alpha[1]);
                            engine.fpx.fpcorrectionPRIME(alpha[1]);
                            if (Fpx.subarrayEquals(rp, alpha, 2 * engine.params.NWORDS_FIELD))
                            {
                                D[k] = t;
                                break;
                            }
                        }
                    }
                }
                else
                {
                    for (int t = 1; t <= ell_emodw / 2; t++)
                    {
                        if (Fpx.subarrayEquals(rp, CT1, engine.params.NWORDS_FIELD * (2 * (ellw / 2) * (Dlen - 1) + 2 * (t - 1)), 2 * engine.params.NWORDS_FIELD))
                        {
                            D[k] = -t;
                            break;
                        }
                        else
                        {
                            engine.fpx.fp2copy(CT1, engine.params.NWORDS_FIELD * (2 * ((ellw / 2) * (Dlen - 1) + (t - 1))), alpha);
                            engine.fpx.fpnegPRIME(alpha[1]);
                            engine.fpx.fpcorrectionPRIME(alpha[1]);
                            if (Fpx.subarrayEquals(rp, alpha, 2 * engine.params.NWORDS_FIELD))
                            {
                                D[k] = t;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }


    // Traverse a Pohlig-Hellman optimal strategy to solve a discrete log in a group of order ell^e
    // The leaves of the tree will be used to recover the signed digits which are numbers from +/-{0,1... Ceil((ell^w-1)/2)}
    // Assume the integer w divides the exponent e
    void Traverse_w_div_e_fullsigned(long[][] r, int j, int k, int z, int[] P, long[] CT, int[] D, int Dlen, int ellw, int w)
    {
        long[][] rp = new long[2][engine.params.NWORDS_FIELD], alpha = new long[2][engine.params.NWORDS_FIELD];

        if (z > 1)
        {
            int t = P[z];
            engine.fpx.fp2copy(r, rp);
            for (int i = 0; i < z - t; i++)
            {
                if ((ellw & 1) == 0)
                {
                    for (int ii = 0; ii < w; ii++)
                    {
                        engine.fpx.sqr_Fp2_cycl(rp, engine.params.Montgomery_one);
                    }
                }
                else
                {
                    for (int ii = 0; ii < w; ii++)
                    {
                        engine.fpx.cube_Fp2_cycl(rp, engine.params.Montgomery_one);
                    }
                }
            }

            Traverse_w_div_e_fullsigned(rp, j + (z - t), k, t, P, CT, D, Dlen, ellw, w);

            engine.fpx.fp2copy(r, rp);
            for (int h = k; h < k + t; h++)
            {
                if (D[h] != 0)
                {
                    if (D[h] < 0)
                    {
                        engine.fpx.fp2copy(CT, engine.params.NWORDS_FIELD * (2 * ((j + h) * (ellw / 2) + (-D[h] - 1))), alpha);
                        engine.fpx.fpnegPRIME(alpha[1]);
                        engine.fpx.fp2mul_mont(rp, alpha, rp);
                    }
                    else
                    {
                        engine.fpx.fp2mul_mont(rp, CT, engine.params.NWORDS_FIELD * (2 * ((j + h) * (ellw / 2) + (D[h] - 1))), rp);
                    }
                }
            }
            Traverse_w_div_e_fullsigned(rp, j, k + t, z - t, P, CT, D, Dlen, ellw, w);
        }
        else
        {
            engine.fpx.fp2copy(r, rp);
            engine.fpx.fp2correction(rp);

            if (engine.fpx.is_felm_zero(rp[1]) && Fpx.subarrayEquals(rp[0], engine.params.Montgomery_one, engine.params.NWORDS_FIELD))
            {
                D[k] = 0;
            }
            else
            {
                for (int t = 1; t <= ellw / 2; t++)
                {
                    if (Fpx.subarrayEquals(rp, CT, engine.params.NWORDS_FIELD * (2 * ((Dlen - 1) * (ellw / 2) + (t - 1))), 2 * engine.params.NWORDS_FIELD))
                    {
                        D[k] = -t;
                        break;
                    }
                    else
                    {
                        engine.fpx.fp2copy(CT, engine.params.NWORDS_FIELD * (2 * ((Dlen - 1) * (ellw / 2) + (t - 1))), alpha);
                        engine.fpx.fpnegPRIME(alpha[1]);
                        engine.fpx.fpcorrectionPRIME(alpha[1]);
                        if (Fpx.subarrayEquals(rp, alpha, 2 * engine.params.NWORDS_FIELD))
                        {
                            D[k] = t;
                            break;
                        }
                    }
                }
            }
        }
    }
    ///

    //Pairing
    private static final int t_points = 2;

    private void Tate3_pairings(PointProjFull[] Qj, long[][][] f)
    {
        long[] x = new long[engine.params.NWORDS_FIELD],
            y = new long[engine.params.NWORDS_FIELD],
            l1 = new long[engine.params.NWORDS_FIELD],
            l2 = new long[engine.params.NWORDS_FIELD],
            n1 = new long[engine.params.NWORDS_FIELD],
            n2 = new long[engine.params.NWORDS_FIELD],
            x2 = new long[engine.params.NWORDS_FIELD],
            x23 = new long[engine.params.NWORDS_FIELD],
            x2p3 = new long[engine.params.NWORDS_FIELD];

        long[][][] xQ2s = new long[t_points][2][engine.params.NWORDS_FIELD],
            finv = new long[2 * t_points][2][engine.params.NWORDS_FIELD];
        long[][] one = new long[2][engine.params.NWORDS_FIELD],
            t0 = new long[2][engine.params.NWORDS_FIELD],
            t1 = new long[2][engine.params.NWORDS_FIELD],
            t2 = new long[2][engine.params.NWORDS_FIELD],
            t3 = new long[2][engine.params.NWORDS_FIELD],
            t4 = new long[2][engine.params.NWORDS_FIELD],
            t5 = new long[2][engine.params.NWORDS_FIELD],
            g = new long[2][engine.params.NWORDS_FIELD],
            h = new long[2][engine.params.NWORDS_FIELD],
            tf = new long[2][engine.params.NWORDS_FIELD];


        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, one[0]);

        for (int j = 0; j < t_points; j++)
        {
            engine.fpx.fp2copy(one, f[j]);
            engine.fpx.fp2copy(one, f[j + t_points]);
            engine.fpx.fp2sqr_mont(Qj[j].X, xQ2s[j]);
        }
        for (int k = 0; k < engine.params.OBOB_EXPON - 1; k++)
        {
            System.arraycopy(engine.params.T_tate3, engine.params.NWORDS_FIELD * (6 * k + 0), l1, 0, engine.params.NWORDS_FIELD);
            System.arraycopy(engine.params.T_tate3, engine.params.NWORDS_FIELD * (6 * k + 1), l2, 0, engine.params.NWORDS_FIELD);
            System.arraycopy(engine.params.T_tate3, engine.params.NWORDS_FIELD * (6 * k + 2), n1, 0, engine.params.NWORDS_FIELD);
            System.arraycopy(engine.params.T_tate3, engine.params.NWORDS_FIELD * (6 * k + 3), n2, 0, engine.params.NWORDS_FIELD);
            System.arraycopy(engine.params.T_tate3, engine.params.NWORDS_FIELD * (6 * k + 4), x23, 0, engine.params.NWORDS_FIELD);
            System.arraycopy(engine.params.T_tate3, engine.params.NWORDS_FIELD * (6 * k + 5), x2p3, 0, engine.params.NWORDS_FIELD);
            for (int j = 0; j < t_points; j++)
            {
                engine.fpx.fpmul_mont(Qj[j].X[0], l1, t0[0]);
                engine.fpx.fpmul_mont(Qj[j].X[1], l1, t0[1]);
                engine.fpx.fpmul_mont(Qj[j].X[0], l2, t2[0]);
                engine.fpx.fpmul_mont(Qj[j].X[1], l2, t2[1]);
                engine.fpx.fpaddPRIME(xQ2s[j][0], x23, t4[0]);
                engine.fpx.fpcopy(xQ2s[j][1], 0, t4[1]);
                engine.fpx.fpmul_mont(Qj[j].X[0], x2p3, t5[0]);
                engine.fpx.fpmul_mont(Qj[j].X[1], x2p3, t5[1]);
                engine.fpx.fp2sub(t0, Qj[j].Y, t1);
                engine.fpx.fpaddPRIME(t1[0], n1, t1[0]);
                engine.fpx.fp2sub(t2, Qj[j].Y, t3);
                engine.fpx.fpaddPRIME(t3[0], n2, t3[0]);
                engine.fpx.fp2mul_mont(t1, t3, g);
                engine.fpx.fp2sub(t4, t5, h);
                engine.fpx.fp2_conj(h, h);
                engine.fpx.fp2mul_mont(g, h, g);

                engine.fpx.fp2sqr_mont(f[j], tf);
                engine.fpx.fp2mul_mont(f[j], tf, f[j]);
                engine.fpx.fp2mul_mont(f[j], g, f[j]);

                engine.fpx.fpsubPRIME(t0[1], Qj[j].Y[0], t1[0]);
                engine.fpx.fpaddPRIME(t0[0], Qj[j].Y[1], t1[1]);
                engine.fpx.fpnegPRIME(t1[1]);
                engine.fpx.fpaddPRIME(t1[1], n1, t1[1]);
                engine.fpx.fpsubPRIME(t2[1], Qj[j].Y[0], t3[0]);
                engine.fpx.fpaddPRIME(t2[0], Qj[j].Y[1], t3[1]);
                engine.fpx.fpnegPRIME(t3[1]);
                engine.fpx.fpaddPRIME(t3[1], n2, t3[1]);

                engine.fpx.fp2mul_mont(t1, t3, g);
                engine.fpx.fp2add(t4, t5, h);
                engine.fpx.fp2_conj(h, h);
                engine.fpx.fp2mul_mont(g, h, g);

                engine.fpx.fp2sqr_mont(f[j + t_points], tf);
                engine.fpx.fp2mul_mont(f[j + t_points], tf, f[j + t_points]);
                engine.fpx.fp2mul_mont(f[j + t_points], g, f[j + t_points]);
            }
        }
        for (int j = 0; j < t_points; j++)
        {
            System.arraycopy(engine.params.T_tate3, engine.params.NWORDS_FIELD * (6 * (engine.params.OBOB_EXPON - 1) + 0), x, 0, engine.params.NWORDS_FIELD);
            System.arraycopy(engine.params.T_tate3, engine.params.NWORDS_FIELD * (6 * (engine.params.OBOB_EXPON - 1) + 1), y, 0, engine.params.NWORDS_FIELD);
            System.arraycopy(engine.params.T_tate3, engine.params.NWORDS_FIELD * (6 * (engine.params.OBOB_EXPON - 1) + 2), l1, 0, engine.params.NWORDS_FIELD);
            System.arraycopy(engine.params.T_tate3, engine.params.NWORDS_FIELD * (6 * (engine.params.OBOB_EXPON - 1) + 3), x2, 0, engine.params.NWORDS_FIELD);

            engine.fpx.fpsubPRIME(Qj[j].X[0], x, t0[0]);
            engine.fpx.fpcopy(Qj[j].X[1], 0, t0[1]);
            engine.fpx.fpmul_mont(l1, t0[0], t1[0]);
            engine.fpx.fpmul_mont(l1, t0[1], t1[1]);
            engine.fpx.fp2sub(t1, Qj[j].Y, t2);
            engine.fpx.fpaddPRIME(t2[0], y, t2[0]);
            engine.fpx.fp2mul_mont(t0, t2, g);
            engine.fpx.fpsubPRIME(Qj[j].X[0], x2, h[0]);
            engine.fpx.fpcopy(Qj[j].X[1], 0, h[1]);
            engine.fpx.fpnegPRIME(h[1]);
            engine.fpx.fp2mul_mont(g, h, g);

            engine.fpx.fp2sqr_mont(f[j], tf);
            engine.fpx.fp2mul_mont(f[j], tf, f[j]);
            engine.fpx.fp2mul_mont(f[j], g, f[j]);

            engine.fpx.fpaddPRIME(Qj[j].X[0], x, t0[0]);
            engine.fpx.fpmul_mont(l1, t0[0], t1[0]);
            engine.fpx.fpsubPRIME(Qj[j].Y[0], t1[1], t2[0]);
            engine.fpx.fpaddPRIME(Qj[j].Y[1], t1[0], t2[1]);
            engine.fpx.fpsubPRIME(t2[1], y, t2[1]);
            engine.fpx.fp2mul_mont(t0, t2, g);
            engine.fpx.fpaddPRIME(Qj[j].X[0], x2, h[0]);
            engine.fpx.fp2mul_mont(g, h, g);

            engine.fpx.fp2sqr_mont(f[j + t_points], tf);
            engine.fpx.fp2mul_mont(f[j + t_points], tf, f[j + t_points]);
            engine.fpx.fp2mul_mont(f[j + t_points], g, f[j + t_points]);
        }

        // Final exponentiation:
        engine.fpx.mont_n_way_inv(f, 2 * t_points, finv);
        for (int j = 0; j < 2 * t_points; j++)
        {
            final_exponentiation_3_torsion(f[j], finv[j], f[j]);
        }
    }

    // The final exponentiation for pairings in the 3-torsion group. Raising the value f to the power (p^2-1)/3^eB.
    private void final_exponentiation_3_torsion(long[][] f, long[][] finv, long[][] fout)
    {
        long[] one = new long[engine.params.NWORDS_FIELD];
        long[][] temp = new long[2][engine.params.NWORDS_FIELD];
        int i;

        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, one);

        // f = f^p
        engine.fpx.fp2_conj(f, temp);
        engine.fpx.fp2mul_mont(temp, finv, temp);              // temp = f^(p-1)

        for (i = 0; i < engine.params.OALICE_BITS; i++)
        {
            engine.fpx.sqr_Fp2_cycl(temp, one);
        }
        engine.fpx.fp2copy(temp, fout);
    }

    private void Tate2_pairings(PointProj P, PointProj Q, PointProjFull[] Qj, long[][][] f)
    {
        long[] x, y, x_, y_, l1;
        long[][][] finv = new long[2 * t_points][2][engine.params.NWORDS_FIELD];

        long[][] x_first, y_first,
            one = new long[2][engine.params.NWORDS_FIELD],
            l1_first = new long[2][engine.params.NWORDS_FIELD],
            t0 = new long[2][engine.params.NWORDS_FIELD],
            t1 = new long[2][engine.params.NWORDS_FIELD],
            g = new long[2][engine.params.NWORDS_FIELD],
            h = new long[2][engine.params.NWORDS_FIELD];

        int x_Offset, y_Offset, l1Offset, xOffset, yOffset;


        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, one[0]);

        for (int j = 0; j < t_points; j++)
        {
            engine.fpx.fp2copy(one, f[j]);
            engine.fpx.fp2copy(one, f[j + t_points]);
        }

        // Pairings with P
        x_first = P.X;
        y_first = P.Z;

        x_Offset = 0;
        y_Offset = 1;
        x_ = engine.params.T_tate2_firststep_P;
        y_ = engine.params.T_tate2_firststep_P;

        engine.fpx.fpcopy(engine.params.T_tate2_firststep_P, 2 * engine.params.NWORDS_FIELD, l1_first[0]);
        engine.fpx.fpcopy(engine.params.T_tate2_firststep_P, 3 * engine.params.NWORDS_FIELD, l1_first[1]);


        for (int j = 0; j < t_points; j++)
        {
            engine.fpx.fp2sub(Qj[j].X, x_first, t0);
            engine.fpx.fp2sub(Qj[j].Y, y_first, t1);
            engine.fpx.fp2mul_mont(l1_first, t0, t0);
            engine.fpx.fp2sub(t0, t1, g);

            engine.fpx.fpsubPRIME(Qj[j].X[0], engine.params.T_tate2_firststep_P, x_Offset, h[0]);
            engine.fpx.fpcopy(Qj[j].X[1], 0, h[1]);
            engine.fpx.fpnegPRIME(h[1]);
            engine.fpx.fp2mul_mont(g, h, g);

            engine.fpx.fp2sqr_mont(f[j], f[j]);
            engine.fpx.fp2mul_mont(f[j], g, f[j]);
        }
        xOffset = 0;
        yOffset = 1 * engine.params.NWORDS_FIELD;
        x = x_;
        y = y_;

        for (int k = 0; k < engine.params.OALICE_BITS - 2; k++)
        {

            x_ = engine.params.T_tate2_P;
            y_ = engine.params.T_tate2_P;
            l1 = engine.params.T_tate2_P;
            x_Offset = engine.params.NWORDS_FIELD * (3 * k + 0);
            y_Offset = engine.params.NWORDS_FIELD * (3 * k + 1);
            l1Offset = engine.params.NWORDS_FIELD * (3 * k + 2);
            for (int j = 0; j < t_points; j++)
            {
                engine.fpx.fpsubPRIME(x, xOffset, Qj[j].X[0], t0[1]);
                engine.fpx.fpmul_mont(l1, l1Offset, t0[1], t0[1]);
                engine.fpx.fpmul_mont(l1, l1Offset, Qj[j].X[1], t0[0]);
                engine.fpx.fpsubPRIME(Qj[j].Y[1], y, yOffset, t1[1]);
                engine.fpx.fpsubPRIME(t0[1], t1[1], g[1]);
                engine.fpx.fpsubPRIME(t0[0], Qj[j].Y[0], g[0]);

                engine.fpx.fpsubPRIME(Qj[j].X[0], x_, x_Offset, h[0]);
                engine.fpx.fpcopy(Qj[j].X[1], 0, h[1]);
                engine.fpx.fpnegPRIME(h[1]);
                engine.fpx.fp2mul_mont(g, h, g);

                engine.fpx.fp2sqr_mont(f[j], f[j]);
                engine.fpx.fp2mul_mont(f[j], g, f[j]);
            }
            x = x_;
            y = y_;
            yOffset = y_Offset;
            xOffset = x_Offset;
        }
        for (int j = 0; j < t_points; j++)
        {
            engine.fpx.fpsubPRIME(Qj[j].X[0], x, xOffset, g[0]);
            engine.fpx.fpcopy(Qj[j].X[1], 0, g[1]);
            engine.fpx.fp2sqr_mont(f[j], f[j]);
            engine.fpx.fp2mul_mont(f[j], g, f[j]);
        }

        // Pairings with Q
        x_first = Q.X;
        y_first = Q.Z;
        x_ = engine.params.T_tate2_firststep_Q;
        y_ = engine.params.T_tate2_firststep_Q;
        x_Offset = 0;
        y_Offset = 1 * engine.params.NWORDS_FIELD;

        engine.fpx.fpcopy(engine.params.T_tate2_firststep_Q, 2 * engine.params.NWORDS_FIELD, l1_first[0]);
        engine.fpx.fpcopy(engine.params.T_tate2_firststep_Q, 3 * engine.params.NWORDS_FIELD, l1_first[1]);

        for (int j = 0; j < t_points; j++)
        {
            engine.fpx.fp2sub(Qj[j].X, x_first, t0);
            engine.fpx.fp2sub(Qj[j].Y, y_first, t1);
            engine.fpx.fp2mul_mont(l1_first, t0, t0);
            engine.fpx.fp2sub(t0, t1, g);

            engine.fpx.fpsubPRIME(Qj[j].X[0], x_, x_Offset, h[0]);
            engine.fpx.fpcopy(Qj[j].X[1], 0, h[1]);
            engine.fpx.fpnegPRIME(h[1]);
            engine.fpx.fp2mul_mont(g, h, g);

            engine.fpx.fp2sqr_mont(f[j + t_points], f[j + t_points]);
            engine.fpx.fp2mul_mont(f[j + t_points], g, f[j + t_points]);
        }
        x = x_;
        y = y_;
        yOffset = y_Offset;
        xOffset = x_Offset;

        for (int k = 0; k < engine.params.OALICE_BITS - 2; k++)
        {
            x_ = engine.params.T_tate2_Q;
            y_ = engine.params.T_tate2_Q;
            l1 = engine.params.T_tate2_Q;

            x_Offset = engine.params.NWORDS_FIELD * (3 * k + 0);
            y_Offset = engine.params.NWORDS_FIELD * (3 * k + 1);
            l1Offset = engine.params.NWORDS_FIELD * (3 * k + 2);
            for (int j = 0; j < t_points; j++)
            {
                engine.fpx.fpsubPRIME(Qj[j].X[0], x, xOffset, t0[0]);
                engine.fpx.fpmul_mont(l1, l1Offset, t0[0], t0[0]);
                engine.fpx.fpmul_mont(l1, l1Offset, Qj[j].X[1], t0[1]);
                engine.fpx.fpsubPRIME(Qj[j].Y[0], y, yOffset, t1[0]);
                engine.fpx.fpsubPRIME(t0[0], t1[0], g[0]);
                engine.fpx.fpsubPRIME(t0[1], Qj[j].Y[1], g[1]);

                engine.fpx.fpsubPRIME(Qj[j].X[0], x_, x_Offset, h[0]);
                engine.fpx.fpcopy(Qj[j].X[1], 0, h[1]);
                engine.fpx.fpnegPRIME(h[1]);
                engine.fpx.fp2mul_mont(g, h, g);

                engine.fpx.fp2sqr_mont(f[j + t_points], f[j + t_points]);
                engine.fpx.fp2mul_mont(f[j + t_points], g, f[j + t_points]);
            }
            x = x_;
            y = y_;
            yOffset = y_Offset;
            xOffset = x_Offset;
        }
        // Last iteration
        for (int j = 0; j < t_points; j++)
        {
            engine.fpx.fpsubPRIME(Qj[j].X[0], x, xOffset, g[0]);
            engine.fpx.fpcopy(Qj[j].X[1], 0, g[1]);

            engine.fpx.fp2sqr_mont(f[j + t_points], f[j + t_points]);
            engine.fpx.fp2mul_mont(f[j + t_points], g, f[j + t_points]);
        }

        // Final exponentiation:
        engine.fpx.mont_n_way_inv(f, 2 * t_points, finv);
        for (int j = 0; j < 2 * t_points; j++)
        {
            final_exponentiation_2_torsion(f[j], finv[j], f[j]);
        }
    }

    // The final exponentiation for pairings in the 2^eA-torsion group. Raising the value f to the power (p^2-1)/2^eA.
    private void final_exponentiation_2_torsion(long[][] f, long[][] finv, long[][] fout)
    {
        long[] one = new long[engine.params.NWORDS_FIELD];
        long[][] temp = new long[2][engine.params.NWORDS_FIELD];
        int i;

        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, one);

        // f = f^p
        engine.fpx.fp2_conj(f, temp);
        engine.fpx.fp2mul_mont(temp, finv, temp);              // temp = f^(p-1)

        for (i = 0; i < engine.params.OBOB_EXPON; i++)
        {
            engine.fpx.cube_Fp2_cycl(temp, one);
        }
        engine.fpx.fp2copy(temp, fout);
    }
}
