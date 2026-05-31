package org.bouncycastle.pqc.crypto.haetae;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.util.Arrays;

public class HAETAESigner
    implements MessageSigner
{
    private static final byte[] EMPTY_CONTEXT = new byte[0];
    private byte[] pre;
    private SecureRandom random;
    private HAETAEParameters params;
    private HAETAEPublicKeyParameters pubKey;
    private HAETAEPrivateKeyParameters privKey;

    @Override
    public void init(boolean forSigning, CipherParameters param)
    {
        pre = EMPTY_CONTEXT;
        if (param instanceof ParametersWithContext)
        {
            ParametersWithContext withContext = (ParametersWithContext)param;
            pre = withContext.getContext();
            param = withContext.getParameters();

            if (pre.length > 256)
            {
                throw new IllegalArgumentException("context too long");
            }
        }

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
        byte[] sig = new byte[params.getCryptoBytes()];
        random.nextBytes(rnd);
        HAETAEEngine engine = new HAETAEEngine(params);
        engine.cryptoSignSignatureInternal(sig, message, pre, rnd, privKey.getEncoded());
        return sig;
    }

    @Override
    public boolean verifySignature(byte[] message, byte[] signature)
    {
        HAETAEEngine engine = new HAETAEEngine(params);
        return engine.cryptoSignVerifyInternal(signature, message, pre, pubKey.getEncoded());
    }
}
