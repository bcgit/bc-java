package org.bouncycastle.pqc.crypto.saber;

import java.security.SecureRandom;

import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.util.SecretWithEncapsulationImpl;

public class SABERKEMGenerator
    implements EncapsulatedSecretGenerator
{
    // the source of randomness
    private final SecureRandom sr;

    public SABERKEMGenerator(SecureRandom random)
    {
        this.sr = random;
    }

    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        SABERPublicKeyParameters key = (SABERPublicKeyParameters)recipientKey;
        SABEREngine engine = key.getParameters().getEngine();
        byte[] cipher_text = new byte[engine.getCipherTextSize()];
        byte[] sessionKey = new byte[engine.getSessionKeySize()];
        engine.crypto_kem_enc(cipher_text, sessionKey, key.getPublicKey(), sr);
        return new SecretWithEncapsulationImpl(sessionKey, cipher_text);
    }
}
