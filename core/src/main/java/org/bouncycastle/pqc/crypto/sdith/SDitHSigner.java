package org.bouncycastle.pqc.crypto.sdith;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;

/**
 * SDitH (Syndrome-Decoding-in-the-Head) signer for the Hypercube variant.
 * <p>
 * Implements {@link MessageSigner} (one-shot whole-message signing) — the
 * signature scheme hashes the message inside the protocol so there is no
 * benefit to a streaming {@code Signer} API. Returned signatures are the raw
 * SDitH signature bytes (the reference KAT generator appends the message
 * itself; that concatenation is left to the caller / a JCA wrapper).
 */
public class SDitHSigner
    implements MessageSigner
{
    private SDitHParameters parameters;
    private SDitHPrivateKeyParameters privKey;
    private SDitHPublicKeyParameters pubKey;
    private SecureRandom random;

    public SDitHSigner()
    {
    }

    public void init(boolean forSigning, CipherParameters param)
    {
        // The JCA SignatureSpi wraps the key parameters in ParametersWithContext via
        // BaseDeterministicOrRandomSignature.reInit; SDitH itself has no context-byte
        // support yet, so unwrap and ignore the context.
        if (param instanceof ParametersWithContext)
        {
            param = ((ParametersWithContext)param).getParameters();
        }

        if (forSigning)
        {
            pubKey = null;
            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom withRandom = (ParametersWithRandom)param;
                privKey = (SDitHPrivateKeyParameters)withRandom.getParameters();
                random = withRandom.getRandom();
            }
            else
            {
                privKey = (SDitHPrivateKeyParameters)param;
                random = CryptoServicesRegistrar.getSecureRandom();
            }
            parameters = privKey.getParameters();
        }
        else
        {
            privKey = null;
            random = null;
            pubKey = (SDitHPublicKeyParameters)param;
            parameters = pubKey.getParameters();
        }
    }

    public byte[] generateSignature(byte[] message)
    {
        if (privKey == null)
        {
            throw new IllegalStateException("SDitHSigner not initialised for signing");
        }
        if (parameters.getVariant() == SDitHParameters.VARIANT_THRESHOLD)
        {
            SDitHThresholdEngine engine = new SDitHThresholdEngine(parameters, random);
            SDitHEngine.SDitHPrivateKeyExpanded expanded = engine.expandPrivateKey(
                privKey.getHASeed(), privKey.getY(), privKey.getSA(), privKey.getQPoly(), privKey.getPPoly());
            return engine.sign(expanded, message, 0, message.length);
        }
        SDitHEngine engine = new SDitHEngine(parameters, random);
        SDitHEngine.SDitHPrivateKeyExpanded expanded = engine.expandPrivateKey(
            privKey.getHASeed(), privKey.getY(), privKey.getSA(), privKey.getQPoly(), privKey.getPPoly());
        return engine.sign(expanded, message, 0, message.length);
    }

    public boolean verifySignature(byte[] message, byte[] signature)
    {
        if (pubKey == null)
        {
            throw new IllegalStateException("SDitHSigner not initialised for verification");
        }
        SecureRandom rng = random == null ? CryptoServicesRegistrar.getSecureRandom() : random;
        if (parameters.getVariant() == SDitHParameters.VARIANT_THRESHOLD)
        {
            SDitHThresholdEngine engine = new SDitHThresholdEngine(parameters, rng);
            SDitHEngine.SDitHPublicKeyExpanded expanded = engine.expandPublicKey(pubKey.getHASeed(), pubKey.getY());
            return engine.verify(expanded, message, 0, message.length, signature, 0, signature.length);
        }
        SDitHEngine engine = new SDitHEngine(parameters, rng);
        SDitHEngine.SDitHPublicKeyExpanded expanded = engine.expandPublicKey(pubKey.getHASeed(), pubKey.getY());
        return engine.verify(expanded, message, 0, message.length, signature, 0, signature.length);
    }
}
