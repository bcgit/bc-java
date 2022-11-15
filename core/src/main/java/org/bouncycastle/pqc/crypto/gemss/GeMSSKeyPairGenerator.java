package org.bouncycastle.pqc.crypto.gemss;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.digests.SHAKEDigest;


public class GeMSSKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;
    private GeMSSParameters parameters;

    @Override
    public void init(KeyGenerationParameters param)
    {
        random = param.getRandom();
        parameters = ((GeMSSKeyGenerationParameters)param).getParameters();
    }

    @Override
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        GeMSSEngine engine = parameters.getEngine();
        int i;
        byte[] seed = sec_rand(engine.SIZE_SEED_SK);
        int NB_COEFS_HFEPOLY = (2 + engine.HFEDegJ + ((engine.HFEDegI * (engine.HFEDegI + 1)) >>> 1));
        int NB_COEFS_HFEVPOLY = (NB_COEFS_HFEPOLY + (engine.NB_MONOMIAL_VINEGAR - 1) + (engine.HFEDegI + 1) * engine.HFEv);
        int NB_UINT_HFEVPOLY = NB_COEFS_HFEVPOLY * engine.NB_WORD_GFqn;
        int sk_uncomp_length = ((NB_UINT_HFEVPOLY + (engine.LTRIANGULAR_NV_SIZE << 1) + (engine.LTRIANGULAR_N_SIZE << 1) + engine.SIZE_VECTOR_t)) << 3;
        Pointer F = new Pointer(sk_uncomp_length >>> 3);
        byte[] sk_uncomp = new byte[sk_uncomp_length];
        SHAKEDigest shakeDigest = new SHAKEDigest(engine.ShakeBitStrength);
        shakeDigest.update(seed, 0, engine.SIZE_SEED_SK);//engine.SIZE_SEED_SK
        shakeDigest.doFinal(sk_uncomp, 0, sk_uncomp_length);
        byte[] sk = new byte[engine.SIZE_SEED_SK];
        final int SIZE_PK_HFE = (engine.NB_MONOMIAL_PK * engine.HFEm + 7) >> 3;
        byte[] pk = new byte[SIZE_PK_HFE];
        System.arraycopy(seed, 0, sk, 0, sk.length);
        F.fill(0, sk_uncomp, 0, sk_uncomp.length);
        engine.cleanMonicHFEv_gf2nx(F);
        Pointer Q = new Pointer(engine.MQnv_GFqn_SIZE);
        int ret;
        if (engine.HFEDeg > 34)
        {
            ret = engine.genSecretMQS_gf2_opt(Q, F);
            if (ret != 0)
            {
                throw new IllegalArgumentException("Error");
            }
        }
        Pointer S = new Pointer(engine.MATRIXnv_SIZE);
        Pointer T = new Pointer(S);
        Pointer L = new Pointer(F, NB_UINT_HFEVPOLY);
        Pointer U = new Pointer(L, engine.LTRIANGULAR_NV_SIZE);
        engine.cleanLowerMatrix(L, GeMSSEngine.FunctionParams.NV);
        engine.cleanLowerMatrix(U, GeMSSEngine.FunctionParams.NV);
        /* Compute Q'=S*Q*St (with Q an upper triangular matrix) */
        engine.invMatrixLU_gf2(S, L, U, GeMSSEngine.FunctionParams.NV);
        if (engine.HFEDeg <= 34)
        {
            ret = engine.interpolateHFE_FS_ref(Q, F, S);
            if (ret != 0)
            {
                throw new IllegalArgumentException("Error");
            }
        }
        else
        {
            engine.changeVariablesMQS64_gf2(Q, S);
            //changeVariablesMQS_gf2(engine, Q, S);
        }
        L.move(engine.LTRIANGULAR_NV_SIZE << 1);
        U.changeIndex(L.getIndex() + engine.LTRIANGULAR_N_SIZE);
        engine.cleanLowerMatrix(L, GeMSSEngine.FunctionParams.N);
        engine.cleanLowerMatrix(U, GeMSSEngine.FunctionParams.N);
        engine.invMatrixLU_gf2(T, L, U, GeMSSEngine.FunctionParams.N);
        if (engine.HFEmr8 != 0)
        {
            final int MQ_GFqm8_SIZE = (engine.NB_MONOMIAL_PK * engine.NB_BYTES_GFqm + ((8 - (engine.NB_BYTES_GFqm & 7)) & 7));
            Pointer pk_tmp = new PointerUnion(MQ_GFqm8_SIZE);
            //mixEquationsMQS8_gf2(pk_tmp,Q,T);
            i = (engine.NB_BYTES_GFqm & 7) != 0 ? 1 : 0;
            Pointer Q_cp = new Pointer(Q);
            PointerUnion pk_cp = new PointerUnion((PointerUnion)pk_tmp);
            /* for each monomial of MQS and pk */
            for (; i < engine.NB_MONOMIAL_PK; ++i)
            {
                engine.vecMatProduct(pk_cp, Q_cp, T, 0, GeMSSEngine.FunctionParams.M);
                /* next monomial */
                Q_cp.move(engine.NB_WORD_GFqn);
                pk_cp.moveNextBytes(engine.NB_BYTES_GFqm);
            }
            /* Last monomial: we fill the last bytes of pk without 64-bit cast. */
            if ((engine.NB_BYTES_GFqm & 7) != 0)
            {
                Pointer pk_last = new Pointer(engine.NB_WORD_GF2m);
                engine.vecMatProduct(pk_last, Q_cp, T, 0, GeMSSEngine.FunctionParams.M);
                for (i = 0; i < engine.NB_WORD_GF2m; ++i)//engine.HFEmq
                {
                    pk_cp.set(i, pk_last.get(i));
                }
            }
            pk_cp.indexReset();
            if (engine.HFENr8 != 0 && (engine.HFEmr8 > 1))
            {
                engine.convMQS_one_eq_to_hybrid_rep8_uncomp_gf2(pk, pk_cp);
            }
            else
            {
                engine.convMQS_one_eq_to_hybrid_rep8_comp_gf2(pk, pk_cp);
            }
        }
        return new AsymmetricCipherKeyPair(new GeMSSPublicKeyParameters(parameters, pk),
            new GeMSSPrivateKeyParameters(parameters, sk));
    }

    private byte[] sec_rand(int n)
    {
        byte[] rv = new byte[n];
        random.nextBytes(rv);
        return rv;
    }

    private int changeVariablesMQS_gf2(GeMSSEngine engine, Pointer MQS_orig, Pointer S)
    {
        Pointer tmp = new Pointer(engine.NB_WORD_GFqn);
        Pointer MQS = new Pointer(MQS_orig);
        Pointer MQS_cpi = new Pointer(MQS);
        Pointer S_cpi = new Pointer(S);
        int i, j;
        /* Tmp matrix (n+v)*(n+v) of quadratic terms to compute S*Q */
        Pointer MQS2 = new Pointer(engine.HFEnv * engine.HFEnv * engine.NB_WORD_GFqn);
        /* To avoid the constant of MQS */
        MQS.move(engine.NB_WORD_GFqn);
        /* Step 1: compute MQS2 = S*Q */
        /* Use multiplication by transpose (so by rows of Q) */
        /* It is possible because X*Q*tX = X*tQ*tX (with X = (x1 ... xn)) */
        /* Warning : Q is a upper triangular matrix in GF(q^n) */
        Pointer MQS2_cp = new Pointer(MQS2);
        Pointer S_cpj = new Pointer(S);
        for (j = 0; j < engine.HFEnv; ++j)
        {
            /* initialisation at the first row of Q */
            MQS_cpi.changeIndex(MQS);
            /* for each row of Q */
            for (i = 0; i < engine.HFEnv; ++i)
            {
                /* Compute a dot product */
                engine.vecMatProduct(MQS2_cp, S_cpj, MQS_cpi, i, GeMSSEngine.FunctionParams.NVN_Start);
                MQS_cpi.move(engine.NB_WORD_GFqn * (engine.HFEnv - i));
                /* update the next element to compute */
                MQS2_cp.move(engine.NB_WORD_GFqn);
            }
            S_cpj.move(engine.NB_WORD_GF2nv);
        }
        /* Step 2: compute MQS = MQS2*tS = (S*Q)*tS */
        /* Use multiplication by transpose (so by rows of S) */
        /* Permute MQS and MQS2 */
        Pointer MQS_cpj = new Pointer(MQS2);
        MQS2_cp.changeIndex(MQS);
        S_cpj.changeIndex(S);
        /* First: compute upper triangular result */
        /* for each row j of MQS2 */
        for (j = 0; j < engine.HFEnv; ++j)
        {
            S_cpi.changeIndex(S_cpj);
            /* for each row >=j of S */
            for (i = j; i < engine.HFEnv; ++i)
            {
                /* Compute a dot product with complete rows */
                /* (Init to 0 the res) */
                //vecMatProductnvn_gf2(MQS2_cp, S_cpi, MQS_cpj);
                engine.vecMatProduct(MQS2_cp, S_cpi, MQS_cpj, 0, GeMSSEngine.FunctionParams.NVN);
                /* update the next element to compute */
                MQS2_cp.move(engine.NB_WORD_GFqn);
                /* update the next row of S to use */
                S_cpi.move(engine.NB_WORD_GF2nv);
            }
            /* Next row of MQS2 */
            MQS_cpj.move(engine.NB_WORD_GFqn * engine.HFEnv);
            /* Next row of S because of upper triangular */
            S_cpj.move(engine.NB_WORD_GF2nv);
        }

        /* Second: compute lower triangular result */
        MQS_cpj.changeIndex(MQS2);
        MQS2_cp.changeIndex(MQS);
        S_cpj.changeIndex(S);

        /* for each row j of S */
        for (j = 0; j < engine.HFEnv; ++j)
        {
            /* i=j : the diagonal is already computing */
            MQS2_cp.move(engine.NB_WORD_GFqn);
            /* The line j of MQS2 is useless */
            MQS_cpj.move(engine.HFEnv * engine.NB_WORD_GFqn);
            MQS_cpi.changeIndex(MQS_cpj);
            /* for each row >j of MQS2 */
            for (i = j + 1; i < engine.HFEnv; ++i)
            {
                /* Compute a dot product with complete rows */
                //vecMatProductnvn_gf2(tmp, S_cpj, MQS_cpi);
                engine.vecMatProduct(tmp, S_cpj, MQS_cpi, 0, GeMSSEngine.FunctionParams.NVN);
                MQS2_cp.setXorRange(0, tmp, 0, engine.NB_WORD_GFqn);
                //engine.add2_gf2(MQS2_cp, tmp, engine.NB_WORD_GFqn);
                MQS_cpi.move(engine.NB_WORD_GFqn * engine.HFEnv);
                /* update the next element to compute */
                MQS2_cp.move(engine.NB_WORD_GFqn);
            }
            /* Next row of S */
            S_cpj.move(engine.NB_WORD_GF2nv);
        }
        return 0;
    }
}
