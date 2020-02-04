package org.bouncycastle.pqc.crypto.xmss;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

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
    }

    /**
     * Generate a new XMSS private key / public key pair.
     */
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        /* generate private key */
        XMSSPrivateKeyParameters privateKey = generatePrivateKey(params, prng);
        XMSSNode root = privateKey.getBDSState().getRoot();

        privateKey = new XMSSPrivateKeyParameters.Builder(params)
            .withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF())
            .withPublicSeed(privateKey.getPublicSeed()).withRoot(root.getValue())
            .withBDSState(privateKey.getBDSState()).build();

        XMSSPublicKeyParameters  publicKey = new XMSSPublicKeyParameters.Builder(params).withRoot(root.getValue())
            .withPublicSeed(privateKey.getPublicSeed()).build();

        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }

    /**
     * Generate an XMSS private key.
     *
     * @return XMSS private key.
     */
    private XMSSPrivateKeyParameters generatePrivateKey(XMSSParameters params, SecureRandom prng)
    {
        int n = params.getTreeDigestSize();
        byte[] secretKeySeed = new byte[n];
        prng.nextBytes(secretKeySeed);
        byte[] secretKeyPRF = new byte[n];
        prng.nextBytes(secretKeyPRF);
        byte[] publicSeed = new byte[n];
        prng.nextBytes(publicSeed);

        XMSSPrivateKeyParameters privateKey = new XMSSPrivateKeyParameters.Builder(params).withSecretKeySeed(secretKeySeed)
            .withSecretKeyPRF(secretKeyPRF).withPublicSeed(publicSeed)
            .withBDSState(new BDS(params, publicSeed, secretKeySeed, (OTSHashAddress)new OTSHashAddress.Builder().build())).build();

        return privateKey;
    }
}
