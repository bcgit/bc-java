package org.bouncycastle.pqc.crypto.uov;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;

/**
 * Unbalanced Oil and Vinegar (UOV) signer, classic variant. One-shot
 * MessageSigner: the message is absorbed in full inside generateSignature /
 * verifySignature, matching the reference pqov implementation.
 */
public class UOVSigner
    implements MessageSigner
{
    private UOVPrivateKeyParameters privKey;
    private UOVPublicKeyParameters pubKey;
    private SecureRandom random;
    private UOVEngine engine;

    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            pubKey = null;
            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom withRandom = (ParametersWithRandom)param;
                privKey = (UOVPrivateKeyParameters)withRandom.getParameters();
                random = withRandom.getRandom();
            }
            else
            {
                privKey = (UOVPrivateKeyParameters)param;
                random = CryptoServicesRegistrar.getSecureRandom();
            }
            engine = new UOVEngine(privKey.getParameters());
        }
        else
        {
            privKey = null;
            random = null;
            pubKey = (UOVPublicKeyParameters)param;
            engine = new UOVEngine(pubKey.getParameters());
        }
    }

    public byte[] generateSignature(byte[] message)
    {
        if (privKey == null)
        {
            throw new IllegalStateException("UOVSigner not initialised for signing");
        }
        // Use the params-typed overload so the engine borrows the internal
        // byte[] read-only instead of cloning a multi-MB defensive copy
        // through privKey.getEncoded().
        return engine.sign(privKey, message, random);
    }

    public boolean verifySignature(byte[] message, byte[] signature)
    {
        if (pubKey == null)
        {
            throw new IllegalStateException("UOVSigner not initialised for verification");
        }
        return engine.verify(pubKey, message, signature);
    }
}
