package org.bouncycastle.pqc.crypto.sike;


class SIDH
{

    private SIKEEngine engine;

    public SIDH(SIKEEngine engine)
    {
        this.engine = engine;
    }

    // Initialization of basis points
    protected void init_basis(long[] gen, long[][] XP, long[][] XQ, long[][] XR)
    {
       engine.fpx.fpcopy(gen, 0, XP[0]);
       engine.fpx.fpcopy(gen, engine.params.NWORDS_FIELD, XP[1]);
       engine.fpx.fpcopy(gen, 2 * engine.params.NWORDS_FIELD, XQ[0]);
       engine.fpx.fpcopy(gen, 3 * engine.params.NWORDS_FIELD, XQ[1]);
       engine.fpx.fpcopy(gen, 4 * engine.params.NWORDS_FIELD, XR[0]);
       engine.fpx.fpcopy(gen, 5 * engine.params.NWORDS_FIELD, XR[1]);
    }

    // Bob's ephemeral public key generation
    // Input:  a private key PrivateKeyB in the range [0, 2^Floor(Log(2,oB)) - 1].
    // Output: the public key PublicKeyB consisting of 3 elements in GF(p^2) which are encoded by removing leading 0 bytes.
    protected void EphemeralKeyGeneration_B(byte[] sk, byte[] pk)
    {
        PointProj R = new PointProj(engine.params.NWORDS_FIELD),
                phiP = new PointProj(engine.params.NWORDS_FIELD),
                phiQ = new PointProj(engine.params.NWORDS_FIELD),
                phiR = new PointProj(engine.params.NWORDS_FIELD);

        PointProj[] pts = new PointProj[engine.params.MAX_INT_POINTS_BOB];

        long[][] XPB = new long[2][engine.params.NWORDS_FIELD],
                XQB = new long[2][engine.params.NWORDS_FIELD],
                XRB = new long[2][engine.params.NWORDS_FIELD],
                A24plus = new long[2][engine.params.NWORDS_FIELD],
                A24minus = new long[2][engine.params.NWORDS_FIELD],
                A = new long[2][engine.params.NWORDS_FIELD];

        long[][][] coeff = new long[3][2][engine.params.NWORDS_FIELD];
        int i, row, m, index = 0, npts = 0, ii = 0;
        int[] pts_index = new int[engine.params.MAX_INT_POINTS_BOB];
        long[] SecretKeyB = new long[engine.params.NWORDS_ORDER];

        // Initialize basis points
        init_basis(engine.params.B_gen, XPB, XQB, XRB);
        init_basis(engine.params.A_gen, phiP.X, phiQ.X, phiR.X);
        engine.fpx.fpcopy(engine.params.Montgomery_one,0,phiP.Z[0]);
        engine.fpx.fpcopy(engine.params.Montgomery_one,0,phiQ.Z[0]);
        engine.fpx.fpcopy(engine.params.Montgomery_one,0,phiR.Z[0]);

        // Initialize constants: A24minus = A-2C, A24plus = A+2C, where A=6, C=1
        engine.fpx.fpcopy(engine.params.Montgomery_one, 0,A24plus[0]);
        engine.fpx.mp2_add(A24plus, A24plus, A24plus);
        engine.fpx.mp2_add(A24plus, A24plus, A24minus);
        engine.fpx.mp2_add(A24plus, A24minus, A);
        engine.fpx.mp2_add(A24minus, A24minus, A24plus);
        engine.fpx.decode_to_digits(sk, engine.params.MSG_BYTES, SecretKeyB, engine.params.SECRETKEY_B_BYTES, engine.params.NWORDS_ORDER);
        engine.isogeny.LADDER3PT(XPB, XQB, XRB, SecretKeyB, engine.params.BOB, R, A);

        // Traverse tree
        index =0;
        for(row = 1; row < engine.params.MAX_Bob; row++)
        {
            while (index < engine.params.MAX_Bob - row)
            {
                pts[npts] = new PointProj(engine.params.NWORDS_FIELD);
                engine.fpx.fp2copy(R.X, pts[npts].X);
                engine.fpx.fp2copy(R.Z, pts[npts].Z);
                pts_index[npts++] = index;
                m = engine.params.strat_Bob[ii++];
                engine.isogeny.xTPLe(R, R, A24minus, A24plus, m);
                index += m;
            }
            engine.isogeny.get_3_isog(R, A24minus, A24plus, coeff);

            for (i = 0; i < npts; i++)
            {
                engine.isogeny.eval_3_isog(pts[i], coeff);
            }
            engine.isogeny.eval_3_isog(phiP, coeff);
            engine.isogeny.eval_3_isog(phiQ, coeff);
            engine.isogeny.eval_3_isog(phiR, coeff);

            engine.fpx.fp2copy(pts[npts - 1].X, R.X);
            engine.fpx.fp2copy(pts[npts - 1].Z, R.Z);
            index = pts_index[npts - 1];
            npts -= 1;
        }
        engine.isogeny.get_3_isog(R, A24minus, A24plus, coeff);
        engine.isogeny.eval_3_isog(phiP, coeff);
        engine.isogeny.eval_3_isog(phiQ, coeff);
        engine.isogeny.eval_3_isog(phiR, coeff);
        engine.isogeny.inv_3_way(phiP.Z, phiQ.Z, phiR.Z);

        engine.fpx.fp2mul_mont(phiP.X, phiP.Z, phiP.X);
        engine.fpx.fp2mul_mont(phiQ.X, phiQ.Z, phiQ.X);
        engine.fpx.fp2mul_mont(phiR.X, phiR.Z, phiR.X);

        // Format public key
        engine.fpx.fp2_encode(phiP.X, pk, 0);
        engine.fpx.fp2_encode(phiQ.X, pk, engine.params.FP2_ENCODED_BYTES);
        engine.fpx.fp2_encode(phiR.X, pk, 2*engine.params.FP2_ENCODED_BYTES);
    }

    // Alice's ephemeral public key generation
    // Input:  a private key PrivateKeyA in the range [0, 2^eA - 1].
    // Output: the public key PublicKeyA consisting of 3 elements in GF(p^2) which are encoded by removing leading 0 bytes.
    protected void EphemeralKeyGeneration_A(byte[] ephemeralsk, byte[] ct)
    {
        PointProj R = new PointProj(engine.params.NWORDS_FIELD),
                phiP = new PointProj(engine.params.NWORDS_FIELD),
                phiQ = new PointProj(engine.params.NWORDS_FIELD),
                phiR = new PointProj(engine.params.NWORDS_FIELD);

        PointProj[] pts = new PointProj[engine.params.MAX_INT_POINTS_ALICE];

        long[][] XPA = new long[2][engine.params.NWORDS_FIELD],
                XQA = new long[2][engine.params.NWORDS_FIELD],
                XRA = new long[2][engine.params.NWORDS_FIELD],
                A24plus = new long[2][engine.params.NWORDS_FIELD],
                C24 = new long[2][engine.params.NWORDS_FIELD],
                A = new long[2][engine.params.NWORDS_FIELD];

        long[][][] coeff = new long[3][2][engine.params.NWORDS_FIELD];
        int i, row, m, index = 0, npts = 0, ii = 0;
        int[] pts_index = new int[engine.params.MAX_INT_POINTS_ALICE];
        long[] SecretKeyA = new long[engine.params.NWORDS_ORDER];

        // Initialize basis points
        init_basis(engine.params.A_gen, XPA, XQA, XRA);
        init_basis(engine.params.B_gen, phiP.X, phiQ.X, phiR.X);
        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, phiP.Z[0]);
        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, phiQ.Z[0]);
        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, phiR.Z[0]);

        // Initialize constants: A24plus = A+2C, C24 = 4C, where A=6, C=1
        engine.fpx.fpcopy(engine.params.Montgomery_one, 0, A24plus[0]);
        engine.fpx.mp2_add(A24plus, A24plus, A24plus);
        engine.fpx.mp2_add(A24plus, A24plus, C24);
        engine.fpx.mp2_add(A24plus, C24, A);
        engine.fpx.mp2_add(C24, C24, A24plus);

        // Retrieve kernel point
        engine.fpx.decode_to_digits(ephemeralsk, 0, SecretKeyA, engine.params.SECRETKEY_A_BYTES, engine.params.NWORDS_ORDER);
        engine.isogeny.LADDER3PT(XPA, XQA, XRA, SecretKeyA, engine.params.ALICE, R, A);

        if (engine.params.OALICE_BITS % 2 == 1)
        {
            PointProj S = new PointProj(engine.params.NWORDS_FIELD);
            engine.isogeny.xDBLe(R, S, A24plus, C24, (int) (engine.params.OALICE_BITS - 1));
            engine.isogeny.get_2_isog(S, A24plus, C24);
            engine.isogeny.eval_2_isog(phiP, S);
            engine.isogeny.eval_2_isog(phiQ, S);
            engine.isogeny.eval_2_isog(phiR, S);
            engine.isogeny.eval_2_isog(R, S);
        }

        // Traverse tree
        index = 0;
        for (row = 1; row < engine.params.MAX_Alice; row++)
        {
            while (index < engine.params.MAX_Alice-row)
            {
                pts[npts] = new PointProj(engine.params.NWORDS_FIELD);
                engine.fpx.fp2copy(R.X, pts[npts].X);
                engine.fpx.fp2copy(R.Z, pts[npts].Z);
                pts_index[npts++] = index;
                m = engine.params.strat_Alice[ii++];
                engine.isogeny.xDBLe(R, R, A24plus, C24, (int)(2*m));
                index += m;
            }
            engine.isogeny.get_4_isog(R, A24plus, C24, coeff);

            for (i = 0; i < npts; i++)
            {
                engine.isogeny.eval_4_isog(pts[i], coeff);
            }
            engine.isogeny.eval_4_isog(phiP, coeff);
            engine.isogeny.eval_4_isog(phiQ, coeff);
            engine.isogeny.eval_4_isog(phiR, coeff);

            engine.fpx.fp2copy(pts[npts-1].X, R.X);
            engine.fpx.fp2copy(pts[npts-1].Z, R.Z);
            index = pts_index[npts-1];
            npts -= 1;
        }

        engine.isogeny.get_4_isog(R, A24plus, C24, coeff);
        engine.isogeny.eval_4_isog(phiP, coeff);
        engine.isogeny.eval_4_isog(phiQ, coeff);
        engine.isogeny.eval_4_isog(phiR, coeff);

        engine.isogeny.inv_3_way(phiP.Z, phiQ.Z, phiR.Z);
        engine.fpx.fp2mul_mont(phiP.X, phiP.Z, phiP.X);
        engine.fpx.fp2mul_mont(phiQ.X, phiQ.Z, phiQ.X);
        engine.fpx.fp2mul_mont(phiR.X, phiR.Z, phiR.X);

        // Format public key
        engine.fpx.fp2_encode(phiP.X, ct,0);
        engine.fpx.fp2_encode(phiQ.X, ct, engine.params.FP2_ENCODED_BYTES);
        engine.fpx.fp2_encode(phiR.X, ct,2*engine.params.FP2_ENCODED_BYTES);

    }

    // Alice's ephemeral shared secret computation
    // It produces a shared secret key SharedSecretA using her secret key PrivateKeyA and Bob's public key PublicKeyB
    // Inputs: Alice's PrivateKeyA is an integer in the range [0, oA-1].
    //         Bob's PublicKeyB consists of 3 elements in GF(p^2) encoded by removing leading 0 bytes.
    // Output: a shared secret SharedSecretA that consists of one element in GF(p^2) encoded by removing leading 0 bytes.
    protected void EphemeralSecretAgreement_A(byte[] ephemeralsk, byte[] pk, byte[] jinvariant)
    {
        PointProj R = new PointProj(engine.params.NWORDS_FIELD);
        PointProj[] pts = new PointProj[engine.params.MAX_INT_POINTS_ALICE];
        long[][][] PKB = new long[3][2][engine.params.NWORDS_FIELD],
                   coeff = new long[3][2][engine.params.NWORDS_FIELD];
        long[][] jinv = new long[2][engine.params.NWORDS_FIELD],
                 A24plus =  new long[2][engine.params.NWORDS_FIELD],
                 C24 = new long[2][engine.params.NWORDS_FIELD],
                 A = new long[2][engine.params.NWORDS_FIELD];

        int i = 0, row = 0, m = 0, index = 0, npts = 0, ii = 0;
        int[] pts_index = new int[engine.params.MAX_INT_POINTS_ALICE];
        long[] SecretKeyA = new long[engine.params.NWORDS_ORDER];

        // Initialize images of Bob's basis
        engine.fpx.fp2_decode(pk, PKB[0], 0);
        engine.fpx.fp2_decode(pk, PKB[1], engine.params.FP2_ENCODED_BYTES);
        engine.fpx.fp2_decode(pk, PKB[2], 2*engine.params.FP2_ENCODED_BYTES);

        // Initialize constants: A24plus = A+2C, C24 = 4C, where C=1
        engine.isogeny.get_A(PKB[0], PKB[1], PKB[2], A);
        engine.fpx.mp_add(engine.params.Montgomery_one, engine.params.Montgomery_one, C24[0], engine.params.NWORDS_FIELD);
        engine.fpx.mp2_add(A, C24, A24plus);
        engine.fpx.mp_add(C24[0], C24[0], C24[0], engine.params.NWORDS_FIELD);

        // Retrieve kernel point
        engine.fpx.decode_to_digits(ephemeralsk, 0, SecretKeyA, engine.params.SECRETKEY_A_BYTES, engine.params.NWORDS_ORDER);
        engine.isogeny.LADDER3PT(PKB[0], PKB[1], PKB[2], SecretKeyA, engine.params.ALICE, R, A);

        if (engine.params.OALICE_BITS % 2 == 1)
        {
            PointProj S = new PointProj(engine.params.NWORDS_FIELD);

            engine.isogeny.xDBLe(R, S, A24plus, C24, (int) (engine.params.OALICE_BITS - 1));
            engine.isogeny.get_2_isog(S, A24plus, C24);
            engine.isogeny.eval_2_isog(R, S);
        }

        // Traverse tree
        index = 0;
        for (row = 1; row < engine.params.MAX_Alice; row++)
        {
            while (index < engine.params.MAX_Alice-row)
            {
                pts[npts] = new PointProj(engine.params.NWORDS_FIELD);
                engine.fpx.fp2copy(R.X, pts[npts].X);
                engine.fpx.fp2copy(R.Z, pts[npts].Z);
                pts_index[npts++] = index;
                m = engine.params.strat_Alice[ii++];
                engine.isogeny.xDBLe(R, R, A24plus, C24, (int)(2*m));
                index += m;
            }
            engine.isogeny.get_4_isog(R, A24plus, C24, coeff);

            for (i = 0; i < npts; i++)
            {
                engine.isogeny.eval_4_isog(pts[i], coeff);
            }

            engine.fpx.fp2copy(pts[npts-1].X, R.X);
            engine.fpx.fp2copy(pts[npts-1].Z, R.Z);
            index = pts_index[npts-1];
            npts -= 1;
        }

        engine.isogeny.get_4_isog(R, A24plus, C24, coeff);
        engine.fpx.mp2_add(A24plus, A24plus, A24plus);
        engine.fpx.fp2sub(A24plus, C24, A24plus);
        engine.fpx.fp2add(A24plus, A24plus, A24plus);
        engine.isogeny.j_inv(A24plus, C24, jinv);
        engine.fpx.fp2_encode(jinv, jinvariant, 0);    // Format shared secret
    }

    // Bob's ephemeral shared secret computation
    // It produces a shared secret key SharedSecretB using his secret key PrivateKeyB and Alice's public key PublicKeyA
    // Inputs: Bob's PrivateKeyB is an integer in the range [0, 2^Floor(Log(2,oB)) - 1].
    //         Alice's PublicKeyA consists of 3 elements in GF(p^2) encoded by removing leading 0 bytes.
    // Output: a shared secret SharedSecretB that consists of one element in GF(p^2) encoded by removing leading 0 bytes.
    protected void EphemeralSecretAgreement_B(byte[] sk, byte[] ct, byte[] jinvariant_)
    {
        PointProj R = new PointProj(engine.params.NWORDS_FIELD);
        PointProj[] pts = new PointProj[engine.params.MAX_INT_POINTS_BOB];
        long[][][] coeff = new long[3][2][engine.params.NWORDS_FIELD],
                PKB = new long[3][2][engine.params.NWORDS_FIELD];
        long[][] jinv = new long[2][engine.params.NWORDS_FIELD],
                A24plus = new long[2][engine.params.NWORDS_FIELD],
                A24minus = new long[2][engine.params.NWORDS_FIELD],
                A = new long[2][engine.params.NWORDS_FIELD];
        int i, row, m, index = 0, npts = 0, ii = 0;
        int[] pts_index = new int[engine.params.MAX_INT_POINTS_BOB];
        long[] SecretKeyB = new long[engine.params.NWORDS_ORDER];

        // Initialize images of Alice's basis
        engine.fpx.fp2_decode(ct,  PKB[0], 0);
        engine.fpx.fp2_decode(ct, PKB[1], engine.params.FP2_ENCODED_BYTES);
        engine.fpx.fp2_decode(ct, PKB[2], 2*engine.params.FP2_ENCODED_BYTES);

        // Initialize constants: A24plus = A+2C, A24minus = A-2C, where C=1
        engine.isogeny.get_A(PKB[0], PKB[1], PKB[2], A);
        engine.fpx.mp_add(engine.params.Montgomery_one, engine.params.Montgomery_one, A24minus[0], engine.params.NWORDS_FIELD);
        engine.fpx.mp2_add(A, A24minus, A24plus);
        engine.fpx.mp2_sub_p2(A, A24minus, A24minus);

        // Retrieve kernel point
        engine.fpx.decode_to_digits(sk, engine.params.MSG_BYTES, SecretKeyB, engine.params.SECRETKEY_B_BYTES, engine.params.NWORDS_ORDER);
        engine.isogeny.LADDER3PT(PKB[0], PKB[1], PKB[2], SecretKeyB, engine.params.BOB, R, A);

        // Traverse tree
        index = 0;
        for (row = 1; row < engine.params.MAX_Bob; row++)
        {
            while (index < engine.params.MAX_Bob-row)
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

            engine.fpx.fp2copy(pts[npts-1].X, R.X);
            engine.fpx.fp2copy(pts[npts-1].Z, R.Z);
            index = pts_index[npts-1];
            npts -= 1;
        }

        engine.isogeny.get_3_isog(R, A24minus, A24plus, coeff);
        engine.fpx.fp2add(A24plus, A24minus, A);
        engine.fpx.fp2add(A, A, A);
        engine.fpx.fp2sub(A24plus, A24minus, A24plus);
        engine.isogeny.j_inv(A, A24plus, jinv);
        engine.fpx.fp2_encode(jinv, jinvariant_, 0);    // Format shared secret
    }

}
