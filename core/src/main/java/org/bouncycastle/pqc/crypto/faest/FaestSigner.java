package org.bouncycastle.pqc.crypto.faest;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;

/**
 * FAEST signer / verifier. Wraps {@link Faest#sign} and {@link Faest#verify}
 * to expose the standard {@link MessageSigner} interface.
 */
public class FaestSigner
    implements MessageSigner
{
    private FaestParameters params;
    private FaestPublicKeyParameters pubKey;
    private FaestPrivateKeyParameters privKey;
    private SecureRandom random;

    @Override
    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            pubKey = null;
            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom withRandom = (ParametersWithRandom)param;
                privKey = (FaestPrivateKeyParameters)withRandom.getParameters();
                random = withRandom.getRandom();
            }
            else
            {
                privKey = (FaestPrivateKeyParameters)param;
                random = CryptoServicesRegistrar.getSecureRandom();
            }
            params = privKey.getParameters();
        }
        else
        {
            pubKey = (FaestPublicKeyParameters)param;
            params = pubKey.getParameters();
            privKey = null;
            random = null;
        }
    }

    @Override
    public byte[] generateSignature(byte[] message)
    {
        if (privKey == null)
        {
            throw new IllegalStateException("FaestSigner not initialized for signing");
        }
        byte[] rho = new byte[params.getLambdaBytes()];
        random.nextBytes(rho);

        byte[] sig = new byte[params.getSigSize()];
        Faest.sign(sig, message, privKey.getOwfKey(), privKey.getOwfInput(),
            pubKeyOwfOutputFromPrivate(privKey), rho, params);
        return sig;
    }

    @Override
    public boolean verifySignature(byte[] message, byte[] signature)
    {
        if (pubKey == null)
        {
            throw new IllegalStateException("FaestSigner not initialized for verification");
        }
        if (signature.length != params.getSigSize())
        {
            return false;
        }
        return Faest.verify(message, signature, pubKey.getOwfInput(), pubKey.getOwfOutput(),
            params) == 0;
    }

    /** Re-derive the OWF output from a private key (used during sign because the
     *  upstream sign API needs both the secret OWF key and the public OWF output). */
    private static byte[] pubKeyOwfOutputFromPrivate(FaestPrivateKeyParameters priv)
    {
        FaestParameters p = priv.getParameters();
        byte[] out = new byte[p.getOwfOutputSize()];
        Faest.owf(priv.getOwfKey(), priv.getOwfInput(), out, p);
        return out;
    }
}
