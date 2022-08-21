package org.bouncycastle.pqc.crypto.sike;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.util.SecretWithEncapsulationImpl;

public class SIKEKEMGenerator
    implements EncapsulatedSecretGenerator
{
    // the source of randomness
    private final SecureRandom sr;


    public SIKEKEMGenerator(SecureRandom random)
    {
        this.sr = random;
    }

    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("SIKEKEM", 0, recipientKey, CryptoServicePurpose.ENCRYPTION));

        SIKEPublicKeyParameters key = (SIKEPublicKeyParameters)recipientKey;
        SIKEEngine engine = key.getParameters().getEngine();

        return generateEncapsulated(recipientKey, engine.getDefaultSessionKeySize());
    }

    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey, int sessionKeySizeInBits)
    {
        // -DM System.err.println
        System.err.println("WARNING: the SIKE algorithm is only for research purposes, insecure");
        SIKEPublicKeyParameters key = (SIKEPublicKeyParameters)recipientKey;
        SIKEEngine engine = key.getParameters().getEngine();
        byte[] cipher_text = new byte[engine.getCipherTextSize()];
        byte[] sessionKey = new byte[sessionKeySizeInBits / 8];
        engine.crypto_kem_enc(cipher_text, sessionKey, key.getPublicKey(), sr);
        return new SecretWithEncapsulationImpl(sessionKey, cipher_text);
    }
}
