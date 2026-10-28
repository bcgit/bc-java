package org.bouncycastle.crypto.generators;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.kems.mlkem.MLKEMEngine;
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;

public class MLKEMKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private MLKEMParameters mlkemParams;

    private SecureRandom random;

    private void initialize(
        KeyGenerationParameters param)
    {
        this.mlkemParams = ((MLKEMKeyGenerationParameters)param).getParameters();
        this.random = param.getRandom();

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("ML-KEMKeyGen",
            mlkemParams.getClassicalSecurityStrength(), mlkemParams, CryptoServicePurpose.KEYGEN));
    }

    private AsymmetricCipherKeyPair genKeyPair()
    {
        MLKEMEngine engine = MLKEMEngine.getInstance(mlkemParams);

        byte[][] keyPair = engine.generateKemKeyPair(random);

        MLKEMPublicKeyParameters pubKey = new MLKEMPublicKeyParameters(mlkemParams, keyPair[0], keyPair[1]);
        MLKEMPrivateKeyParameters privKey = new MLKEMPrivateKeyParameters(mlkemParams,  keyPair[2], keyPair[3], keyPair[4], keyPair[0], keyPair[1], keyPair[5]);
        
        return new AsymmetricCipherKeyPair(pubKey, privKey);
    }

    public void init(KeyGenerationParameters param)
    {
        this.initialize(param);
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        return genKeyPair();
    }
}
