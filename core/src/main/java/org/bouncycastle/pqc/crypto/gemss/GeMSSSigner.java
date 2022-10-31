package org.bouncycastle.pqc.crypto.gemss;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;


public class GeMSSSigner
    implements MessageSigner
{
    private GeMSSPrivateKeyParameters privKey;
    private GeMSSPublicKeyParameters pubKey;
    private SecureRandom random;

    public GeMSSSigner()
    {

    }


    @Override
    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            if (param instanceof ParametersWithRandom)
            {
                privKey = ((GeMSSPrivateKeyParameters)((ParametersWithRandom)param).getParameters());
                random = ((ParametersWithRandom)param).getRandom();
            }
            else
            {
                privKey = (GeMSSPrivateKeyParameters)param;
                random = CryptoServicesRegistrar.getSecureRandom();
            }
        }
        else
        {
            pubKey = (GeMSSPublicKeyParameters)param;
        }

    }

    @Override
    public byte[] generateSignature(byte[] message)
    {
        GeMSSEngine engine = privKey.getParameters().getEngine();

        byte[] sm8 = new byte[message.length + engine.SIZE_SIGN_HFE];
        System.arraycopy(message, 0, sm8, engine.SIZE_SIGN_HFE, message.length);
        engine.signHFE_FeistelPatarin(random, sm8, message, 0, message.length, privKey.sk);
        return sm8;
    }

    @Override
    public boolean verifySignature(byte[] message, byte[] signature)
    {
        GeMSSEngine engine = pubKey.getParameters().getEngine();
        int ret = engine.crypto_sign_open(pubKey.getPK(), message, signature);
//        Pointer pk_tmp = new Pointer(1 + engine.NB_WORD_UNCOMP_EQ * engine.HFEmr8);//if (engine.HFEmr8 != 0)
//        PointerUnion pk = new PointerUnion(pubKey.getPK());
//        int i;
//        long val = 0;
//        if (engine.HFENr8 != 0 && (engine.HFEmr8 > 1))
//        {
//            PointerUnion pk_cp = new PointerUnion(pk);
//            pk_cp.moveNextBytes(engine.ACCESS_last_equations8 - 1);
//            for (i = 0; i < engine.HFEmr8 - 1; ++i)
//            {
//                /* Last byte of the equation */
//                pk_cp.moveNextBytes(engine.NB_BYTES_EQUATION);
//                val ^= ((pk_cp.getByte() & 0xFFL) >>> engine.HFENr8) << (i * engine.HFENr8c);
//            }
//        }
//        if (engine.HFEmr8 != 0)
//        {
//            long cst = 0;
//            PointerUnion pk64 = new PointerUnion(pk);
//            for (i = 0; i < (engine.HFEmr8 - 1); i++)
//            {
//                pk64.setByteIndex(engine.ACCESS_last_equations8 + i * engine.NB_BYTES_EQUATION);
//                cst ^= engine.convMQ_uncompressL_gf2(new Pointer(pk_tmp, 1 + i * engine.NB_WORD_UNCOMP_EQ), pk64) << i;
//            }
//            pk64.setByteIndex(engine.ACCESS_last_equations8 + i * engine.NB_BYTES_EQUATION);
//            /* The last equation in input is smaller because compressed */
//            cst ^= engine.convMQ_last_uncompressL_gf2(new Pointer(pk_tmp, 1 + i * engine.NB_WORD_UNCOMP_EQ), pk64) << i;
//            if (engine.HFENr8 != 0 && (engine.HFEmr8 > 1))
//            {
//                /* Number of lost bits by the zero padding of each equation (without the last) */
//                final int LOST_BITS = ((engine.HFEmr8 - 1) * engine.HFENr8c);
//                if (engine.HFEnvr == 0)
//                {
//                    pk_tmp.setXor(1 + (i + 1) * engine.NB_WORD_UNCOMP_EQ - 1, val << (64 - LOST_BITS));
//                }
//                else if (engine.HFEnvr > LOST_BITS)
//                {
//                    pk_tmp.setXor(1 + (i + 1) * engine.NB_WORD_UNCOMP_EQ - 1, val << (engine.HFEnvr - LOST_BITS));
//                }
//                else if (engine.HFEnvr == LOST_BITS)
//                {
//                    pk_tmp.set(1 + (i + 1) * engine.NB_WORD_UNCOMP_EQ - 1, val);
//                }
//                else if (engine.HFEnvr < LOST_BITS)
//                {
//                    pk_tmp.setXor(1 + (i + 1) * engine.NB_WORD_UNCOMP_EQ - 2, val << (64 - (LOST_BITS - engine.HFEnvr)));
//                    pk_tmp.set(1 + (i + 1) * engine.NB_WORD_UNCOMP_EQ - 1, val >> (LOST_BITS - engine.HFEnvr));
//                }
//            }
//            cst <<= engine.HFEmr - engine.HFEmr8;
//            pk_tmp.set(cst);
//        }
//        int ret = 0;
//        if (engine.HFEmr8 != 0)
//        {
//            ret = engine.sign_openHFE_huncomp_pk(message, message.length, signature, pk, new PointerUnion(pk_tmp));
//        }
        return ret != 0;
    }
}
