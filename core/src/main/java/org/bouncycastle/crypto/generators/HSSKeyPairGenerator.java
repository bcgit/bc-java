package org.bouncycastle.crypto.generators;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.params.HSSKeyGenerationParameters;
import org.bouncycastle.crypto.params.HSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.LMSParameters;

public class HSSKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    HSSKeyGenerationParameters param;

    public void init(KeyGenerationParameters param)
    {
        this.param = (HSSKeyGenerationParameters)param;

        // the strength of the hierarchy is that of its weakest level
        LMSParameters[] lmsParams = this.param.getLmsParameters();
        int bitsOfSecurity = Integer.MAX_VALUE;
        for (int i = 0; i != lmsParams.length; i++)
        {
            bitsOfSecurity = Math.min(bitsOfSecurity, lmsParams[i].getLMSigParam().getClassicalSecurityStrength());
        }
        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("HSSKeyGen",
            bitsOfSecurity, lmsParams, CryptoServicePurpose.KEYGEN));
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        HSSPrivateKeyParameters privKey = HSSPrivateKeyParameters.generate(param);

        return new AsymmetricCipherKeyPair(privKey.getPublicKey(), privKey);
    }
}
