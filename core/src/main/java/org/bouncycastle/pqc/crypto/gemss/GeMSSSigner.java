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

    public byte[] generateSignature(byte[] message)
    {
        GeMSSEngine engine = privKey.getParameters().getEngine();
        final int SIZE_SIGN_HFE = ((engine.HFEnv + (engine.NB_ITE - 1) * (engine.HFEnv - engine.HFEm)) + 7) >>> 3;
        byte[] sm8 = new byte[message.length + SIZE_SIGN_HFE];
        System.arraycopy(message, 0, sm8, SIZE_SIGN_HFE, message.length);
        engine.signHFE_FeistelPatarin(random, sm8, message, 0, message.length, privKey.sk);
        return sm8;
    }

    public boolean verifySignature(byte[] message, byte[] signature)
    {
        GeMSSEngine engine = pubKey.getParameters().getEngine();
        int ret = engine.crypto_sign_open(pubKey.getPK(), message, signature);
        return ret != 0;
    }
}
