package org.bouncycastle.pqc.crypto.mlkem;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.util.SecretWithEncapsulationImpl;

public class MLKEMGenerator
    implements EncapsulatedSecretGenerator
{
    private final SecureRandom random;

    public MLKEMGenerator(SecureRandom random)
    {
        this.random = CryptoServicesRegistrar.getSecureRandom(random);
    }

    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        byte[] randBytes = new byte[32];
        random.nextBytes(randBytes);

        return internalGenerateEncapsulated(recipientKey, randBytes);
    }

    public SecretWithEncapsulation internalGenerateEncapsulated(AsymmetricKeyParameter recipientKey, byte[] randBytes)
    {
        MLKEMPublicKeyParameters key = (MLKEMPublicKeyParameters)recipientKey;
        MLKEMEngine engine = key.getParameters().getEngine();

        byte[][] kemEncrypt = engine.kemEncrypt(key, randBytes);
        return new SecretWithEncapsulationImpl(kemEncrypt[0], kemEncrypt[1]);
    }
}
