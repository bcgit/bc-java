package org.bouncycastle.crypto.generators;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.params.XMSSKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.signers.xmss.XMSSEngine;

/**
 * Key pair generator for XMSS keys.
 */
public final class XMSSKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private XMSSParameters params;
    private SecureRandom prng;

    /**
     * Base constructor...
     */
    public XMSSKeyPairGenerator()
    {
    }

    public void init(
        KeyGenerationParameters param)
    {
        XMSSKeyGenerationParameters parameters = (XMSSKeyGenerationParameters)param;

        this.prng = parameters.getRandom();
        this.params = parameters.getParameters();

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("XMSSKeyGen",
            params.getClassicalSecurityStrength(), params, CryptoServicePurpose.KEYGEN));
    }

    /**
     * Generate a new XMSS private key / public key pair.
     */
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        return XMSSEngine.generateKeyPair(params, prng);
    }
}
