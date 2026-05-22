package org.bouncycastle.pqc.crypto.mqom;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;

/**
 * MQOM v2.1 lightweight signer. Implements the BCPQC one-shot
 * {@link MessageSigner} contract: {@link #generateSignature(byte[])} takes the
 * whole message and {@link #verifySignature(byte[], byte[])} takes the message
 * plus the candidate signature. Messages are hashed internally per the spec
 * (Hash2 in algorithm 3).
 *
 * <p>Per-call randomness (mseed, salt) is drawn from the {@code SecureRandom}
 * supplied via {@link ParametersWithRandom}; pass an explicit
 * {@code ParametersWithRandom} to make signing deterministic or to inject a
 * KAT-style fixed RNG.
 */
public class MQOMSigner
    implements MessageSigner
{
    private MQOMPublicKeyParameters pubKey;
    private MQOMPrivateKeyParameters privKey;
    private SecureRandom random;
    private MQOMEngine engine;

    public MQOMSigner()
    {
    }

    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            pubKey = null;
            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom withRandom = (ParametersWithRandom)param;
                privKey = (MQOMPrivateKeyParameters)withRandom.getParameters();
                random = withRandom.getRandom();
            }
            else
            {
                privKey = (MQOMPrivateKeyParameters)param;
                random = CryptoServicesRegistrar.getSecureRandom();
            }
            engine = MQOMEngine.getInstance(privKey.getParameters());
        }
        else
        {
            pubKey = (MQOMPublicKeyParameters)param;
            privKey = null;
            random = null;
            engine = MQOMEngine.getInstance(pubKey.getParameters());
        }
    }

    public byte[] generateSignature(byte[] message)
    {
        if (privKey == null)
        {
            throw new IllegalStateException("MQOMSigner not initialised for signing");
        }
        MQOMParameters params = privKey.getParameters();
        byte[] mseed = new byte[params.getSeedSize()];
        byte[] salt = new byte[params.getSaltSize()];
        random.nextBytes(mseed);
        random.nextBytes(salt);
        return engine.sign(privKey.getEncoded(), message, salt, mseed);
    }

    public boolean verifySignature(byte[] message, byte[] signature)
    {
        if (pubKey == null)
        {
            throw new IllegalStateException("MQOMSigner not initialised for verification");
        }
        return engine.verify(pubKey.getEncoded(), message, signature);
    }
}
