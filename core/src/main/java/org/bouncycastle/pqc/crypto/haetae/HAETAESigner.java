package org.bouncycastle.pqc.crypto.haetae;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.util.Arrays;

public class HAETAESigner
    implements MessageSigner
{

    private SecureRandom random;
    private HAETAEParameters params;
    private HAETAEPublicKeyParameters pubKey;
    private HAETAEPrivateKeyParameters privKey;

    @Override
    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            pubKey = null;

            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom withRandom = (ParametersWithRandom)param;
                privKey = (HAETAEPrivateKeyParameters)withRandom.getParameters();
                random = withRandom.getRandom();
            }
            else
            {
                privKey = (HAETAEPrivateKeyParameters)param;
                random = CryptoServicesRegistrar.getSecureRandom();
            }
            params = privKey.getParameters();
        }
        else
        {
            pubKey = (HAETAEPublicKeyParameters)param;
            params = pubKey.getParameters();
            privKey = null;
            random = null;
        }
    }

    @Override
    public byte[] generateSignature(byte[] message)
    {
        byte[] rnd = new byte[32];
        byte[] ctx = new byte[1];
        byte[] sig = new byte[params.getCryptoBytes()];
        random.nextBytes(rnd);
        random.nextBytes(ctx);
        byte[] pre = new byte[(ctx[0] & 0xff)];
        random.nextBytes(pre);
        HAETAEEngine engine = new HAETAEEngine(params);
        engine.cryptoSignSignatureInternal(sig, message, Arrays.concatenate(ctx, pre), rnd, privKey.getEncoded());
        return sig;
    }

    @Override
    public boolean verifySignature(byte[] message, byte[] signature)
    {
        return false;
    }
}
