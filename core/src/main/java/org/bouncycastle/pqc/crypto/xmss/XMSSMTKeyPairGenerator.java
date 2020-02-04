package org.bouncycastle.pqc.crypto.xmss;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Key pair generator for XMSS^MT keys.
 */
public final class XMSSMTKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private XMSSMTParameters params;
    private XMSSParameters xmssParams;

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

        prng = parameters.getRandom();
        this.params = parameters.getParameters();
        this.xmssParams = params.getXMSSParameters();
    }

    /**
     * Generate a new XMSSMT private key / public key pair.
     */
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        XMSSMTPrivateKeyParameters privateKey;
        XMSSMTPublicKeyParameters publicKey;

            /* generate XMSSMT private key */
        privateKey = generatePrivateKey(new XMSSMTPrivateKeyParameters.Builder(params).build().getBDSState());

            /* import to xmss */
        xmssParams.getWOTSPlus().importKeys(new byte[params.getTreeDigestSize()], privateKey.getPublicSeed());

            /* get root */
        int rootLayerIndex = params.getLayers() - 1;
        OTSHashAddress otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withLayerAddress(rootLayerIndex)
            .build();

          		/* store BDS instance of root xmss instance */
        BDS bdsRoot = new BDS(xmssParams, privateKey.getPublicSeed(), privateKey.getSecretKeySeed(), otsHashAddress);
        XMSSNode root = bdsRoot.getRoot();
        privateKey.getBDSState().put(rootLayerIndex, bdsRoot);

            /* set XMSS^MT root / create public key */
        privateKey = new XMSSMTPrivateKeyParameters.Builder(params).withSecretKeySeed(privateKey.getSecretKeySeed())
            .withSecretKeyPRF(privateKey.getSecretKeyPRF()).withPublicSeed(privateKey.getPublicSeed())
            .withRoot(root.getValue()).withBDSState(privateKey.getBDSState()).build();
        publicKey = new XMSSMTPublicKeyParameters.Builder(params).withRoot(root.getValue())
            .withPublicSeed(privateKey.getPublicSeed()).build();

        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }

    private XMSSMTPrivateKeyParameters generatePrivateKey(BDSStateMap bdsState)
    {
        int n = params.getTreeDigestSize();
        byte[] secretKeySeed = new byte[n];
        prng.nextBytes(secretKeySeed);
        byte[] secretKeyPRF = new byte[n];
        prng.nextBytes(secretKeyPRF);
        byte[] publicSeed = new byte[n];
        prng.nextBytes(publicSeed);

        XMSSMTPrivateKeyParameters privateKey = null;

        privateKey = new XMSSMTPrivateKeyParameters.Builder(params).withSecretKeySeed(secretKeySeed)
                .withSecretKeyPRF(secretKeyPRF).withPublicSeed(publicSeed)
                .withBDSState(bdsState).build();

        return privateKey;
    }
}
