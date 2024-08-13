package org.bouncycastle.pqc.crypto.crystals.kyber;

import java.security.SecureRandom;

import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.util.SecretWithEncapsulationImpl;

public class KyberKEMGenerator
    implements EncapsulatedSecretGenerator
{
    // the source of randomness
    private final SecureRandom sr;

    public KyberKEMGenerator(SecureRandom random)
    {
        this.sr = random;
    }

    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        KyberPublicKeyParameters key = (KyberPublicKeyParameters)recipientKey;
        KyberEngine engine = key.getParameters().getEngine();
        engine.init(sr);

        byte[] randBytes = new byte[32];
        engine.getRandomBytes(randBytes);

        byte[][] kemEncrypt = engine.kemEncrypt(key.getEncoded(), randBytes);
        return new SecretWithEncapsulationImpl(kemEncrypt[0], kemEncrypt[1]);
    }
    public SecretWithEncapsulation internalGenerateEncapsulated(AsymmetricKeyParameter recipientKey, byte[] randBytes)
    {
        KyberPublicKeyParameters key = (KyberPublicKeyParameters)recipientKey;
        KyberEngine engine = key.getParameters().getEngine();
        engine.init(sr);

        byte[][] kemEncrypt = engine.kemEncryptInternal(key.getEncoded(), randBytes);
        return new SecretWithEncapsulationImpl(kemEncrypt[0], kemEncrypt[1]);
    }
}
