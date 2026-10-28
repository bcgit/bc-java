package org.bouncycastle.crypto.generators;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.params.XMSSMTKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.signers.xmss.XMSSEngine;

/**
 * Key pair generator for XMSS^MT keys.
 */
public final class XMSSMTKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private XMSSMTParameters params;
    private SecureRandom prng;

    /**
     * Base constructor...
     */
    public XMSSMTKeyPairGenerator()
    {
    }

    public void init(
        KeyGenerationParameters param)
    {
        XMSSMTKeyGenerationParameters parameters = (XMSSMTKeyGenerationParameters)param;

        this.prng = parameters.getRandom();
        this.params = parameters.getParameters();

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("XMSSMTKeyGen",
            params.getClassicalSecurityStrength(), params, CryptoServicePurpose.KEYGEN));
    }

    /**
     * Generate a new XMSSMT private key / public key pair.
     */
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        return XMSSEngine.generateMTKeyPair(params, prng);
    }
}
