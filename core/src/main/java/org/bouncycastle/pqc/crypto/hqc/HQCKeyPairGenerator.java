package org.bouncycastle.pqc.crypto.hqc;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.util.Arrays;

public class HQCKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;
    private HQCParameters parameters;

    @Override
    public void init(KeyGenerationParameters params)
    {
        this.random = params.getRandom();
        this.parameters = ((HQCKeyGenerationParameters)params).getParameters();

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("HQCKeyGen",
            parameters.getClassicalSecurityStrength(), parameters, CryptoServicePurpose.KEYGEN));
    }

    @Override
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        byte[] pk = new byte[parameters.getPublicKeyBytes()];
        byte[] seed = new byte[parameters.getSecretKeyBytes()];

        // the expansion key generation already did is handed to the private key so that its first
        // decapsulation does not repeat it
        byte[] expanded = parameters.getEngine().genKeyPair(pk, seed, random);

        HQCPublicKeyParameters publicKey = new HQCPublicKeyParameters(parameters, pk);
        HQCPrivateKeyParameters privateKey = new HQCPrivateKeyParameters(parameters, seed, expanded);

        Arrays.clear(seed);
        Arrays.clear(expanded);

        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }
}
