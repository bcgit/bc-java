package org.bouncycastle.pqc.crypto.sike;

class Isogeny
{
    SIKEEngine engine;

    Isogeny(SIKEEngine engine)
    {
        this.engine = engine;
    }

    protected void LADDER3PT(long[][] xP, long[][] xQ, long[][] xPQ, long[] m, int AliceOrBob, PointProj R, long[][] A)
    {
        PointProj R0 = new PointProj(engine.params.NWORDS_FIELD),
            R2 = new PointProj(engine.params.NWORDS_FIELD);
        long[][] A24 = new long[2][engine.params.NWORDS_FIELD];
        long mask;
        int i, nbits, bit, swap, prevbit = 0;

        if (AliceOrBob == engine.params.ALICE)
        {
            nbits = engine.params.OALICE_BITS;
        }
        else
        {
            nbits = engine.params.OBOB_BITS - 1;
        }

        // Initializing constant
        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, A24[0]);
        engine.fpx.mp2_add(A24, A24, A24);
        engine.fpx.mp2_add(A, A24, A24);
        engine.fpx.fp2div2(A24, A24);
        engine.fpx.fp2div2(A24, A24);  // A24 = (A+2)/4

        // Initializing points
        engine.fpx.fp2copy(xQ, R0.X);
        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, R0.Z[0]);
        engine.fpx.fp2copy(xPQ, R2.X);
        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, R2.Z[0]);
        engine.fpx.fp2copy(xP, R.X);
        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, R.Z[0]);
        engine.fpx.fpzero((R.Z)[1]);

        // Main loop
        for (i = 0; i < nbits; i++)
        {
            bit = (int)((m[i >>> Internal.LOG2RADIX] >>> (i & (Internal.RADIX - 1))) & 1);
            swap = bit ^ prevbit;
            prevbit = bit;
            mask = 0 - (long)swap;
            swap_points(R, R2, mask);
            xDBLADD(R0, R2, R.X, A24);
            engine.fpx.fp2mul_mont(R2.X, R.Z, R2.X);
        }
        swap = 0 ^ prevbit;
        mask = 0 - (long)swap;
        swap_points(R, R2, mask);
    }

    // Swap points.
    // If option = 0 then P <- P and Q <- Q, else if option = 0xFF...FF then P <- Q and Q <- P
    protected void swap_points(PointProj P, PointProj Q, long option)
    {
        //todo/org : put this in the PointProj class
        long temp;
        int i;

        for (i = 0; i < engine.params.NWORDS_FIELD; i++)
        {
            temp = option & (P.X[0][i] ^ Q.X[0][i]);
            P.X[0][i] = temp ^ P.X[0][i];
            Q.X[0][i] = temp ^ Q.X[0][i];
            temp = option & (P.X[1][i] ^ Q.X[1][i]);
            P.X[1][i] = temp ^ P.X[1][i];
            Q.X[1][i] = temp ^ Q.X[1][i];
            temp = option & (P.Z[0][i] ^ Q.Z[0][i]);
            P.Z[0][i] = temp ^ P.Z[0][i];
            Q.Z[0][i] = temp ^ Q.Z[0][i];
            temp = option & (P.Z[1][i] ^ Q.Z[1][i]);
            P.Z[1][i] = temp ^ P.Z[1][i];
            Q.Z[1][i] = temp ^ Q.Z[1][i];
        }
    }

    // Simultaneous doubling and differential addition.
    // Input: projective Montgomery points P=(XP:ZP) and Q=(XQ:ZQ) such that xP=XP/ZP and xQ=XQ/ZQ, affine difference xPQ=x(P-Q) and Montgomery curve constant A24=(A+2)/4.
    // Output: projective Montgomery points P <- 2*P = (X2P:Z2P) such that x(2P)=X2P/Z2P, and Q <- P+Q = (XQP:ZQP) such that = x(Q+P)=XQP/ZQP.

    protected void xDBLADD(PointProj P, PointProj Q, long[][] xPQ, long[][] A24)
    {
        long[][] t0 = new long[2][engine.params.NWORDS_FIELD],
            t1 = new long[2][engine.params.NWORDS_FIELD],
            t2 = new long[2][engine.params.NWORDS_FIELD];

        engine.fpx.mp2_add(P.X, P.Z, t0);                  // t0 = XP+ZP
        engine.fpx.mp2_sub_p2(P.X, P.Z, t1);               // t1 = XP-ZP
        engine.fpx.fp2sqr_mont(t0, P.X);                   // XP = (XP+ZP)^2
        engine.fpx.mp2_sub_p2(Q.X, Q.Z, t2);               // t2 = XQ-ZQ
        engine.fpx.mp2_add(Q.X, Q.Z, Q.X);                 // XQ = XQ+ZQ
        engine.fpx.fp2mul_mont(t0, t2, t0);                // t0 = (XP+ZP)*(XQ-ZQ)
        engine.fpx.fp2sqr_mont(t1, P.Z);                   // ZP = (XP-ZP)^2
        engine.fpx.fp2mul_mont(t1, Q.X, t1);               // t1 = (XP-ZP)*(XQ+ZQ)
        engine.fpx.mp2_sub_p2(P.X, P.Z, t2);               // t2 = (XP+ZP)^2-(XP-ZP)^2
        engine.fpx.fp2mul_mont(P.X, P.Z, P.X);             // XP = (XP+ZP)^2*(XP-ZP)^2
        engine.fpx.fp2mul_mont(A24, t2, Q.X);              // XQ = A24*[(XP+ZP)^2-(XP-ZP)^2]
        engine.fpx.mp2_sub_p2(t0, t1, Q.Z);                // ZQ = (XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ)
        engine.fpx.mp2_add(Q.X, P.Z, P.Z);                 // ZP = A24*[(XP+ZP)^2-(XP-ZP)^2]+(XP-ZP)^2
        engine.fpx.mp2_add(t0, t1, Q.X);                   // XQ = (XP+ZP)*(XQ-ZQ)+(XP-ZP)*(XQ+ZQ)
        engine.fpx.fp2mul_mont(P.Z, t2, P.Z);              // ZP = [A24*[(XP+ZP)^2-(XP-ZP)^2]+(XP-ZP)^2]*[(XP+ZP)^2-(XP-ZP)^2]
        engine.fpx.fp2sqr_mont(Q.Z, Q.Z);                  // ZQ = [(XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ)]^2
        engine.fpx.fp2sqr_mont(Q.X, Q.X);                  // XQ = [(XP+ZP)*(XQ-ZQ)+(XP-ZP)*(XQ+ZQ)]^2
        engine.fpx.fp2mul_mont(Q.Z, xPQ, Q.Z);             // ZQ = xPQ*[(XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ)]^2
    }

    // Computes [2^e](X:Z) on Montgomery curve with projective constant via e repeated doublings.
    // Input: projective Montgomery x-coordinates P = (XP:ZP), such that xP=XP/ZP and Montgomery curve constants A+2C and 4C.
    // Output: projective Montgomery x-coordinates Q <- (2^e)*P.
    protected void xDBLe(PointProj P, PointProj Q, long[][] A24plus, long[][] C24, int e)
    {
        int i;
        engine.fpx.copy_words(P, Q);

        for (i = 0; i < e; i++)
        {
            xDBL(Q, Q, A24plus, C24);
        }
    }

    // Doubling of a Montgomery point in projective coordinates (X:Z).
    // Input: projective Montgomery x-coordinates P = (X1:Z1), where x1=X1/Z1 and Montgomery curve constants A+2C and 4C.
    // Output: projective Montgomery x-coordinates Q = 2*P = (X2:Z2).
    protected void xDBL(PointProj P, PointProj Q, long[][] A24plus, long[][] C24)
    {
        long[][] t0 = new long[2][engine.params.NWORDS_FIELD],
            t1 = new long[2][engine.params.NWORDS_FIELD];

        engine.fpx.mp2_sub_p2(P.X, P.Z, t0);                // t0 = X1-Z1
        engine.fpx.mp2_add(P.X, P.Z, t1);                   // t1 = X1+Z1
        engine.fpx.fp2sqr_mont(t0, t0);                     // t0 = (X1-Z1)^2
        engine.fpx.fp2sqr_mont(t1, t1);                     // t1 = (X1+Z1)^2
        engine.fpx.fp2mul_mont(C24, t0, Q.Z);               // Z2 = C24*(X1-Z1)^2
        engine.fpx.fp2mul_mont(t1, Q.Z, Q.X);               // X2 = C24*(X1-Z1)^2*(X1+Z1)^2
        engine.fpx.mp2_sub_p2(t1, t0, t1);                  // t1 = (X1+Z1)^2-(X1-Z1)^2
        engine.fpx.fp2mul_mont(A24plus, t1, t0);            // t0 = A24plus*[(X1+Z1)^2-(X1-Z1)^2]
        engine.fpx.mp2_add(Q.Z, t0, Q.Z);                   // Z2 = A24plus*[(X1+Z1)^2-(X1-Z1)^2] + C24*(X1-Z1)^2
        engine.fpx.fp2mul_mont(Q.Z, t1, Q.Z);               // Z2 = [A24plus*[(X1+Z1)^2-(X1-Z1)^2] + C24*(X1-Z1)^2]*[(X1+Z1)^2-(X1-Z1)^2]
    }

    // Tripling of a Montgomery point in projective coordinates (X:Z).
    // Input: projective Montgomery x-coordinates P = (X:Z), where x=X/Z and Montgomery curve constants A24plus = A+2C and A24minus = A-2C.
    // Output: projective Montgomery x-coordinates Q = 3*P = (X3:Z3).
    private void xTPL(PointProj P, PointProj Q, long[][] A24minus, long[][] A24plus)
    {
        long[][] t0 = new long[2][engine.params.NWORDS_FIELD],
            t1 = new long[2][engine.params.NWORDS_FIELD],
            t2 = new long[2][engine.params.NWORDS_FIELD],
            t3 = new long[2][engine.params.NWORDS_FIELD],
            t4 = new long[2][engine.params.NWORDS_FIELD],
            t5 = new long[2][engine.params.NWORDS_FIELD],
            t6 = new long[2][engine.params.NWORDS_FIELD];

        engine.fpx.mp2_sub_p2(P.X, P.Z, t0);               // t0 = X-Z
        engine.fpx.fp2sqr_mont(t0, t2);                    // t2 = (X-Z)^2
        engine.fpx.mp2_add(P.X, P.Z, t1);                  // t1 = X+Z
        engine.fpx.fp2sqr_mont(t1, t3);                    // t3 = (X+Z)^2
        engine.fpx.mp2_add(P.X, P.X, t4);                  // t4 = 2*X
        engine.fpx.mp2_add(P.Z, P.Z, t0);                  // t0 = 2*Z
        engine.fpx.fp2sqr_mont(t4, t1);                    // t1 = 4*X^2
        engine.fpx.mp2_sub_p2(t1, t3, t1);                 // t1 = 4*X^2 - (X+Z)^2
        engine.fpx.mp2_sub_p2(t1, t2, t1);                 // t1 = 4*X^2 - (X+Z)^2 - (X-Z)^2
        engine.fpx.fp2mul_mont(A24plus, t3, t5);           // t5 = A24plus*(X+Z)^2
        engine.fpx.fp2mul_mont(t3, t5, t3);                // t3 = A24plus*(X+Z)^4
        engine.fpx.fp2mul_mont(A24minus, t2, t6);          // t6 = A24minus*(X-Z)^2
        engine.fpx.fp2mul_mont(t2, t6, t2);                // t2 = A24minus*(X-Z)^4
        engine.fpx.mp2_sub_p2(t2, t3, t3);                 // t3 = A24minus*(X-Z)^4 - A24plus*(X+Z)^4
        engine.fpx.mp2_sub_p2(t5, t6, t2);                 // t2 = A24plus*(X+Z)^2 - A24minus*(X-Z)^2
        engine.fpx.fp2mul_mont(t1, t2, t1);                // t1 = [4*X^2 - (X+Z)^2 - (X-Z)^2]*[A24plus*(X+Z)^2 - A24minus*(X-Z)^2]
        engine.fpx.fp2add(t3, t1, t2);                     // t2 = [4*X^2 - (X+Z)^2 - (X-Z)^2]*[A24plus*(X+Z)^2 - A24minus*(X-Z)^2] + A24minus*(X-Z)^4 - A24plus*(X+Z)^4
        engine.fpx.fp2sqr_mont(t2, t2);                    // t2 = t2^2
        engine.fpx.fp2mul_mont(t4, t2, Q.X);               // X3 = 2*X*t2
        engine.fpx.fp2sub(t3, t1, t1);                     // t1 = A24minus*(X-Z)^4 - A24plus*(X+Z)^4 - [4*X^2 - (X+Z)^2 - (X-Z)^2]*[A24plus*(X+Z)^2 - A24minus*(X-Z)^2]
        engine.fpx.fp2sqr_mont(t1, t1);                    // t1 = t1^2
        engine.fpx.fp2mul_mont(t0, t1, Q.Z);               // Z3 = 2*Z*t1
    }

    // Computes [3^e](X:Z) on Montgomery curve with projective constant via e repeated triplings.
    // Input: projective Montgomery x-coordinates P = (XP:ZP), such that xP=XP/ZP and Montgomery curve constants A24plus = A+2C and A24minus = A-2C.
    // Output: projective Montgomery x-coordinates Q <- (3^e)*P.
    protected void xTPLe(PointProj P, PointProj Q, long[][] A24minus, long[][] A24plus, int e)
    {
        int i;
        engine.fpx.copy_words(P, Q);
        for (i = 0; i < e; i++)
        {
            xTPL(Q, Q, A24minus, A24plus);
        }
    }

    // Given the x-coordinates of P, Q, and R, returns the value A corresponding to the Montgomery curve E_A: y^2=x^3+A*x^2+x such that R=Q-P on E_A.
    // Input:  the x-coordinates xP, xQ, and xR of the points P, Q and R.
    // Output: the coefficient A corresponding to the curve E_A: y^2=x^3+A*x^2+x.
    protected void get_A(long[][] xP, long[][] xQ, long[][] xR, long[][] A)
    {
        long[][] t0 = new long[2][engine.params.NWORDS_FIELD],
            t1 = new long[2][engine.params.NWORDS_FIELD],
            one = new long[2][engine.params.NWORDS_FIELD];

        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, one[0]);
        engine.fpx.fp2add(xP, xQ, t1);                     // t1 = xP+xQ
        engine.fpx.fp2mul_mont(xP, xQ, t0);                // t0 = xP*xQ
        engine.fpx.fp2mul_mont(xR, t1, A);                 // A = xR*t1
        engine.fpx.fp2add(t0, A, A);                       // A = A+t0
        engine.fpx.fp2mul_mont(t0, xR, t0);                // t0 = t0*xR
        engine.fpx.fp2sub(A, one, A);                      // A = A-1
        engine.fpx.fp2add(t0, t0, t0);                     // t0 = t0+t0
        engine.fpx.fp2add(t1, xR, t1);                     // t1 = t1+xR
        engine.fpx.fp2add(t0, t0, t0);                     // t0 = t0+t0
        engine.fpx.fp2sqr_mont(A, A);                      // A = A^2
        engine.fpx.fp2inv_mont(t0);                        // t0 = 1/t0
        engine.fpx.fp2mul_mont(A, t0, A);                  // A = A*t0
        engine.fpx.fp2sub(A, t1, A);                       // Afinal = A-t1
    }

    // Computes the j-invariant of a Montgomery curve with projective constant.
    // Input: A,C in GF(p^2).
    // Output: j=256*(A^2-3*C^2)^3/(C^4*(A^2-4*C^2)), which is the j-invariant of the Montgomery curve B*y^2=x^3+(A/C)*x^2+x or (equivalently) j-invariant of B'*y^2=C*x^3+A*x^2+C*x.
    protected void j_inv(long[][] A, long[][] C, long[][] jinv)
    {
        long[][] t0 = new long[2][engine.params.NWORDS_FIELD],
            t1 = new long[2][engine.params.NWORDS_FIELD];

        engine.fpx.fp2sqr_mont(A, jinv);                   // jinv = A^2
        engine.fpx.fp2sqr_mont(C, t1);                     // t1 = C^2
        engine.fpx.fp2add(t1, t1, t0);                     // t0 = t1+t1
        engine.fpx.fp2sub(jinv, t0, t0);                   // t0 = jinv-t0
        engine.fpx.fp2sub(t0, t1, t0);                     // t0 = t0-t1
        engine.fpx.fp2sub(t0, t1, jinv);                   // jinv = t0-t1
        engine.fpx.fp2sqr_mont(t1, t1);                    // t1 = t1^2
        engine.fpx.fp2mul_mont(jinv, t1, jinv);            // jinv = jinv*t1
        engine.fpx.fp2add(t0, t0, t0);                     // t0 = t0+t0
        engine.fpx.fp2add(t0, t0, t0);                     // t0 = t0+t0
        engine.fpx.fp2sqr_mont(t0, t1);                    // t1 = t0^2
        engine.fpx.fp2mul_mont(t0, t1, t0);                // t0 = t0*t1
        engine.fpx.fp2add(t0, t0, t0);                     // t0 = t0+t0
        engine.fpx.fp2add(t0, t0, t0);                     // t0 = t0+t0
        engine.fpx.fp2inv_mont(jinv);                      // jinv = 1/jinv
        engine.fpx.fp2mul_mont(jinv, t0, jinv);            // jinv = t0*jinv
    }


    // Computes the corresponding 3-isogeny of a projective Montgomery point (X3:Z3) of order 3.
    // Input:  projective point of order three P = (X3:Z3).
    // Output: the 3-isogenous Montgomery curve with projective coefficient A/C.
    protected void get_3_isog(PointProj P, long[][] A24minus, long[][] A24plus, long[][][] coeff)
    {
        long[][] t0 = new long[2][engine.params.NWORDS_FIELD],
            t1 = new long[2][engine.params.NWORDS_FIELD],
            t2 = new long[2][engine.params.NWORDS_FIELD],
            t3 = new long[2][engine.params.NWORDS_FIELD],
            t4 = new long[2][engine.params.NWORDS_FIELD];

        engine.fpx.mp2_sub_p2(P.X, P.Z, coeff[0]);         // coeff0 = X-Z
        engine.fpx.fp2sqr_mont(coeff[0], t0);              // t0 = (X-Z)^2
        engine.fpx.mp2_add(P.X, P.Z, coeff[1]);            // coeff1 = X+Z
        engine.fpx.fp2sqr_mont(coeff[1], t1);              // t1 = (X+Z)^2
        engine.fpx.mp2_add(P.X, P.X, t3);                  // t3 = 2*X
        engine.fpx.fp2sqr_mont(t3, t3);                    // t3 = 4*X^2
        engine.fpx.fp2sub(t3, t0, t2);                     // t2 = 4*X^2 - (X-Z)^2
        engine.fpx.fp2sub(t3, t1, t3);                     // t3 = 4*X^2 - (X+Z)^2
        engine.fpx.mp2_add(t0, t3, t4);                    // t4 = 4*X^2 - (X+Z)^2 + (X-Z)^2
        engine.fpx.mp2_add(t4, t4, t4);                    // t4 = 2(4*X^2 - (X+Z)^2 + (X-Z)^2)
        engine.fpx.mp2_add(t1, t4, t4);                    // t4 = 8*X^2 - (X+Z)^2 + 2*(X-Z)^2
        engine.fpx.fp2mul_mont(t2, t4, A24minus);          // A24minus = [4*X^2 - (X-Z)^2]*[8*X^2 - (X+Z)^2 + 2*(X-Z)^2]
        engine.fpx.mp2_add(t1, t2, t4);                    // t4 = 4*X^2 + (X+Z)^2 - (X-Z)^2
        engine.fpx.mp2_add(t4, t4, t4);                    // t4 = 2(4*X^2 + (X+Z)^2 - (X-Z)^2)
        engine.fpx.mp2_add(t0, t4, t4);                    // t4 = 8*X^2 + 2*(X+Z)^2 - (X-Z)^2
        engine.fpx.fp2mul_mont(t3, t4, A24plus);           // A24plus = [4*X^2 - (X+Z)^2]*[8*X^2 + 2*(X+Z)^2 - (X-Z)^2]
    }

    // Computes the 3-isogeny R=phi(X:Z), given projective point (X3:Z3) of order 3 on a Montgomery curve and
    // a point P with 2 coefficients in coeff (computed in the function get_3_isog()).
    // Inputs: projective points P = (X3:Z3) and Q = (X:Z).
    // Output: the projective point Q <- phi(Q) = (X3:Z3).
    protected void eval_3_isog(PointProj Q, long[][][] coeff)
    {
        long[][] t0 = new long[2][engine.params.NWORDS_FIELD],
            t1 = new long[2][engine.params.NWORDS_FIELD],
            t2 = new long[2][engine.params.NWORDS_FIELD];

        engine.fpx.mp2_add(Q.X, Q.Z, t0);                  // t0 = X+Z
        engine.fpx.mp2_sub_p2(Q.X, Q.Z, t1);               // t1 = X-Z
        engine.fpx.fp2mul_mont(coeff[0], t0, t0);          // t0 = coeff0*(X+Z)
        engine.fpx.fp2mul_mont(coeff[1], t1, t1);          // t1 = coeff1*(X-Z)
        engine.fpx.mp2_add(t0, t1, t2);                    // t2 = coeff0*(X+Z) + coeff1*(X-Z)
        engine.fpx.mp2_sub_p2(t1, t0, t0);                 // t0 = coeff1*(X-Z) - coeff0*(X+Z)
        engine.fpx.fp2sqr_mont(t2, t2);                    // t2 = [coeff0*(X+Z) + coeff1*(X-Z)]^2
        engine.fpx.fp2sqr_mont(t0, t0);                    // t0 = [coeff1*(X-Z) - coeff0*(X+Z)]^2
        engine.fpx.fp2mul_mont(Q.X, t2, Q.X);              // X3final = X*[coeff0*(X+Z) + coeff1*(X-Z)]^2
        engine.fpx.fp2mul_mont(Q.Z, t0, Q.Z);              // Z3final = Z*[coeff1*(X-Z) - coeff0*(X+Z)]^2
    }

    // 3-way simultaneous inversion
    // Input:  z1,z2,z3
    // Output: 1/z1,1/z2,1/z3 (override inputs).
    protected void inv_3_way(long[][] z1, long[][] z2, long[][] z3)
    {
        long[][] t0 = new long[2][engine.params.NWORDS_FIELD],
            t1 = new long[2][engine.params.NWORDS_FIELD],
            t2 = new long[2][engine.params.NWORDS_FIELD],
            t3 = new long[2][engine.params.NWORDS_FIELD];

        engine.fpx.fp2mul_mont(z1, z2, t0);                // t0 = z1*z2
        engine.fpx.fp2mul_mont(z3, t0, t1);                // t1 = z1*z2*z3
        engine.fpx.fp2inv_mont(t1);                        // t1 = 1/(z1*z2*z3)
        engine.fpx.fp2mul_mont(z3, t1, t2);                // t2 = 1/(z1*z2)
        engine.fpx.fp2mul_mont(t2, z2, t3);                // t3 = 1/z1
        engine.fpx.fp2mul_mont(t2, z1, z2);                // z2 = 1/z2
        engine.fpx.fp2mul_mont(t0, t1, z3);                // z3 = 1/z3
        engine.fpx.fp2copy(t3, z1);                        // z1 = 1/z1
    }

    // Computes the corresponding 2-isogeny of a projective Montgomery point (X2:Z2) of order 2.
    // Input:  projective point of order two P = (X2:Z2).
    // Output: the 2-isogenous Montgomery curve with projective coefficients A/C.
    protected void get_2_isog(PointProj P, long[][] A, long[][] C)
    {
        engine.fpx.fp2sqr_mont(P.X, A);                    // A = X2^2
        engine.fpx.fp2sqr_mont(P.Z, C);                    // C = Z2^2
        engine.fpx.mp2_sub_p2(C, A, A);                    // A = Z2^2 - X2^2
    }

    // Evaluates the isogeny at the point (X:Z) in the domain of the isogeny, given a 2-isogeny phi.
    // Inputs: the projective point P = (X:Z) and the 2-isogeny kernel projetive point Q = (X2:Z2).
    // Output: the projective point P = phi(P) = (X:Z) in the codomain. 
    protected void eval_2_isog(PointProj P, PointProj Q)
    {
        long[][] t0 = new long[2][engine.params.NWORDS_FIELD],
            t1 = new long[2][engine.params.NWORDS_FIELD],
            t2 = new long[2][engine.params.NWORDS_FIELD],
            t3 = new long[2][engine.params.NWORDS_FIELD];

        engine.fpx.mp2_add(Q.X, Q.Z, t0);                  // t0 = X2+Z2
        engine.fpx.mp2_sub_p2(Q.X, Q.Z, t1);               // t1 = X2-Z2
        engine.fpx.mp2_add(P.X, P.Z, t2);                  // t2 = X+Z
        engine.fpx.mp2_sub_p2(P.X, P.Z, t3);               // t3 = X-Z
        engine.fpx.fp2mul_mont(t0, t3, t0);                // t0 = (X2+Z2)*(X-Z)
        engine.fpx.fp2mul_mont(t1, t2, t1);                // t1 = (X2-Z2)*(X+Z)
        engine.fpx.mp2_add(t0, t1, t2);                    // t2 = (X2+Z2)*(X-Z) + (X2-Z2)*(X+Z)
        engine.fpx.mp2_sub_p2(t0, t1, t3);                 // t3 = (X2+Z2)*(X-Z) - (X2-Z2)*(X+Z)
        engine.fpx.fp2mul_mont(P.X, t2, P.X);              // Xfinal
        engine.fpx.fp2mul_mont(P.Z, t3, P.Z);              // Zfinal
    }

    // Computes the corresponding 4-isogeny of a projective Montgomery point (X4:Z4) of order 4.
    // Input:  projective point of order four P = (X4:Z4).
    // Output: the 4-isogenous Montgomery curve with projective coefficients A+2C/4C and the 3 coefficients
    //         that are used to evaluate the isogeny at a point in eval_4_isog().
    protected void get_4_isog(PointProj P, long[][] A24plus, long[][] C24, long[][][] coeff)
    {
        engine.fpx.mp2_sub_p2(P.X, P.Z, coeff[1]);         // coeff[1] = X4-Z4
        engine.fpx.mp2_add(P.X, P.Z, coeff[2]);            // coeff[2] = X4+Z4
        engine.fpx.fp2sqr_mont(P.Z, coeff[0]);             // coeff[0] = Z4^2
        engine.fpx.mp2_add(coeff[0], coeff[0], coeff[0]);  // coeff[0] = 2*Z4^2
        engine.fpx.fp2sqr_mont(coeff[0], C24);             // C24 = 4*Z4^4
        engine.fpx.mp2_add(coeff[0], coeff[0], coeff[0]);  // coeff[0] = 4*Z4^2
        engine.fpx.fp2sqr_mont(P.X, A24plus);              // A24plus = X4^2
        engine.fpx.mp2_add(A24plus, A24plus, A24plus);     // A24plus = 2*X4^2
        engine.fpx.fp2sqr_mont(A24plus, A24plus);          // A24plus = 4*X4^4
    }

    // Evaluates the isogeny at the point (X:Z) in the domain of the isogeny, given a 4-isogeny phi defined
    // by the 3 coefficients in coeff (computed in the function get_4_isog()).
    // Inputs: the coefficients defining the isogeny, and the projective point P = (X:Z).
    // Output: the projective point P = phi(P) = (X:Z) in the codomain.
    protected void eval_4_isog(PointProj P, long[][][] coeff)
    {
        long[][] t0 = new long[2][engine.params.NWORDS_FIELD],
            t1 = new long[2][engine.params.NWORDS_FIELD];

        engine.fpx.mp2_add(P.X, P.Z, t0);                  // t0 = X+Z
        engine.fpx.mp2_sub_p2(P.X, P.Z, t1);               // t1 = X-Z
        engine.fpx.fp2mul_mont(t0, coeff[1], P.X);         // X = (X+Z)*coeff[1]
        engine.fpx.fp2mul_mont(t1, coeff[2], P.Z);         // Z = (X-Z)*coeff[2]
        engine.fpx.fp2mul_mont(t0, t1, t0);                // t0 = (X+Z)*(X-Z)
        engine.fpx.fp2mul_mont(coeff[0], t0, t0);          // t0 = coeff[0]*(X+Z)*(X-Z)
        engine.fpx.mp2_add(P.X, P.Z, t1);                  // t1 = (X-Z)*coeff[2] + (X+Z)*coeff[1]
        engine.fpx.mp2_sub_p2(P.X, P.Z, P.Z);              // Z = (X-Z)*coeff[2] - (X+Z)*coeff[1]
        engine.fpx.fp2sqr_mont(t1, t1);                    // t1 = [(X-Z)*coeff[2] + (X+Z)*coeff[1]]^2
        engine.fpx.fp2sqr_mont(P.Z, P.Z);                  // Z = [(X-Z)*coeff[2] - (X+Z)*coeff[1]]^2
        engine.fpx.mp2_add(t1, t0, P.X);                   // X = coeff[0]*(X+Z)*(X-Z) + [(X-Z)*coeff[2] + (X+Z)*coeff[1]]^2
        engine.fpx.mp2_sub_p2(P.Z, t0, t0);                // t0 = [(X-Z)*coeff[2] - (X+Z)*coeff[1]]^2 - coeff[0]*(X+Z)*(X-Z)
        engine.fpx.fp2mul_mont(P.X, t1, P.X);              // Xfinal
        engine.fpx.fp2mul_mont(P.Z, t0, P.Z);              // Zfinal
    }


}
