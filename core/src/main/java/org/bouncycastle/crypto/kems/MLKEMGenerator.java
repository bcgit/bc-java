package org.bouncycastle.crypto.kems;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.kems.mlkem.MLKEMEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;
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
        byte[] randBytes = new byte[MLKEMEngine.SymBytes];
        random.nextBytes(randBytes);

        return internalGenerateEncapsulated((MLKEMPublicKeyParameters)recipientKey, randBytes);
    }

    /** @deprecated Use {@link #internalGenerateEncapsulated(MLKEMPublicKeyParameters, byte[])} instead. */
    public SecretWithEncapsulation internalGenerateEncapsulated(AsymmetricKeyParameter recipientKey, byte[] randBytes)
    {
        return internalGenerateEncapsulated((MLKEMPublicKeyParameters)recipientKey, randBytes);
    }

    public static SecretWithEncapsulation internalGenerateEncapsulated(MLKEMPublicKeyParameters recipientKey,
        byte[] randBytes)
    {
        if (randBytes.length != MLKEMEngine.SymBytes)
        {
            throw new IllegalArgumentException("'randBytes' has invalid length");
        }

        MLKEMEngine engine = MLKEMEngine.getInstance(recipientKey.getParameters());
        byte[][] kemEncrypt = engine.kemEncrypt(recipientKey, randBytes);
        return new SecretWithEncapsulationImpl(kemEncrypt[0], kemEncrypt[1]);
    }
}
