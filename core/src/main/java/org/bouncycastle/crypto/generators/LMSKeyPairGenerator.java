package org.bouncycastle.crypto.generators;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.params.LMSKeyGenerationParameters;
import org.bouncycastle.crypto.params.LMSPrivateKeyParameters;
import org.bouncycastle.crypto.params.LMSigParameters;

public class LMSKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    LMSKeyGenerationParameters param;

    public void init(KeyGenerationParameters param)
    {
        this.param = (LMSKeyGenerationParameters)param;

        LMSigParameters sigParams = this.param.getParameters().getLMSigParam();
        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("LMSKeyGen",
            sigParams.getClassicalSecurityStrength(), sigParams, CryptoServicePurpose.KEYGEN));
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        LMSPrivateKeyParameters privKey = LMSPrivateKeyParameters.generate(param.getParameters(), param.getRandom());

        return new AsymmetricCipherKeyPair(privKey.getPublicKey(), privKey);
    }
}
