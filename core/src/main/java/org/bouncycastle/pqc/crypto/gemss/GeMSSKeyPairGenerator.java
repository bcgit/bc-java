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
        int i, ret;
        byte[] seed = sec_rand(engine.SIZE_SEED_SK);
        int NB_COEFS_HFEPOLY = (2 + engine.HFEDegJ + ((engine.HFEDegI * (engine.HFEDegI + 1)) >>> 1));
        int NB_COEFS_HFEVPOLY = (NB_COEFS_HFEPOLY + (engine.NB_MONOMIAL_VINEGAR - 1) + (engine.HFEDegI + 1) * engine.HFEv);
        int NB_UINT_HFEVPOLY = NB_COEFS_HFEVPOLY * engine.NB_WORD_GFqn;
        int sk_uncomp_length = ((NB_UINT_HFEVPOLY + (engine.LTRIANGULAR_NV_SIZE << 1) + (engine.LTRIANGULAR_N_SIZE << 1))) << 3;
        Pointer F = new Pointer(sk_uncomp_length >>> 3);
        byte[] sk_uncomp = new byte[sk_uncomp_length];
        SHAKEDigest shakeDigest = new SHAKEDigest(engine.ShakeBitStrength);
        shakeDigest.update(seed, 0, engine.SIZE_SEED_SK);
        shakeDigest.doFinal(sk_uncomp, 0, sk_uncomp_length);
        byte[] sk = new byte[engine.SIZE_SEED_SK];
        final int SIZE_PK_HFE = (engine.NB_MONOMIAL_PK * engine.HFEm + 7) >> 3;
        byte[] pk = new byte[SIZE_PK_HFE];
        System.arraycopy(seed, 0, sk, 0, sk.length);
        F.fill(0, sk_uncomp, 0, sk_uncomp.length);
        engine.cleanMonicHFEv_gf2nx(F);
        Pointer Q = new Pointer(engine.NB_MONOMIAL_PK * engine.NB_WORD_GFqn);
        if (engine.HFEDeg > 34)
        {
            engine.genSecretMQS_gf2_opt(Q, F);
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
        }
        L.move(engine.LTRIANGULAR_NV_SIZE << 1);
        U.changeIndex(L.getIndex() + engine.LTRIANGULAR_N_SIZE);
        engine.cleanLowerMatrix(L, GeMSSEngine.FunctionParams.N);
        engine.cleanLowerMatrix(U, GeMSSEngine.FunctionParams.N);
        engine.invMatrixLU_gf2(T, L, U, GeMSSEngine.FunctionParams.N);
        if (engine.HFEmr8 != 0)
        {
            final int MQ_GFqm8_SIZE = (engine.NB_MONOMIAL_PK * engine.NB_BYTES_GFqm + ((8 - (engine.NB_BYTES_GFqm & 7)) & 7));
            PointerUnion pk_cp = new PointerUnion(MQ_GFqm8_SIZE);
            /* for each monomial of MQS and pk */
            for (i = (engine.NB_BYTES_GFqm & 7) != 0 ? 1 : 0; i < engine.NB_MONOMIAL_PK; ++i)
            {
                engine.vecMatProduct(pk_cp, Q, T, GeMSSEngine.FunctionParams.M);
                /* next monomial */
                Q.move(engine.NB_WORD_GFqn);
                pk_cp.moveNextBytes(engine.NB_BYTES_GFqm);
            }
            /* Last monomial: we fill the last bytes of pk without 64-bit cast. */
            if ((engine.NB_BYTES_GFqm & 7) != 0)
            {
                Pointer pk_last = new Pointer(engine.NB_WORD_GF2m);
                engine.vecMatProduct(pk_last, Q, T, GeMSSEngine.FunctionParams.M);
                for (i = 0; i < engine.NB_WORD_GF2m; ++i)
                {
                    pk_cp.set(i, pk_last.get(i));
                }
            }
            pk_cp.indexReset();
            byte[] pk_U = new byte[engine.HFEmr8 * engine.NB_BYTES_EQUATION];
            engine.convMQS_one_to_last_mr8_equations_gf2(pk_U, pk_cp);
            pk_cp.indexReset();
            if (engine.HFENr8 != 0 && engine.HFEmr8 > 1)
            {
                engine.convMQS_one_eq_to_hybrid_rep8_uncomp_gf2(pk, pk_cp, pk_U);
            }
            else
            {
                engine.convMQS_one_eq_to_hybrid_rep8_comp_gf2(pk, pk_cp, pk_U);
            }
        }
        else
        {
            PointerUnion pk_last = new PointerUnion(engine.NB_WORD_GF2m << 3);
            int pk_p = 0;
            for (i = 0; i < engine.NB_MONOMIAL_PK; ++i)
            {
                engine.vecMatProduct(pk_last, Q, T, GeMSSEngine.FunctionParams.M);
                pk_p = pk_last.toBytesMove(pk, pk_p, engine.NB_BYTES_GFqm);
                pk_last.indexReset();
                Q.move(engine.NB_WORD_GFqn);
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
}
