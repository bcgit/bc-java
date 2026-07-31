package org.bouncycastle.pqc.crypto.smaugt;

import java.security.SecureRandom;

import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.util.SecretWithEncapsulationImpl;

public class SmaugTKEMGenerator
    implements EncapsulatedSecretGenerator
{
    private final SecureRandom sr;

    public SmaugTKEMGenerator(SecureRandom random)
    {
        this.sr = random;
    }

    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        SmaugTPublicKeyParameters key = (SmaugTPublicKeyParameters)recipientKey;
        SmaugTEngine engine = key.getParameters().getEngine();

        byte[] cipherText = new byte[engine.getCipherTextBytes()];
        byte[] sessionKey = new byte[engine.getSharedSecretBytes()];

        engine.cryptoKemEnc(cipherText, sessionKey, key.getPublicKey(), sr);

        return new SecretWithEncapsulationImpl(sessionKey, cipherText);
    }
}
