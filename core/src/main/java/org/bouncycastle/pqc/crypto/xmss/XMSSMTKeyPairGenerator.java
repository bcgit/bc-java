package org.bouncycastle.pqc.crypto.xmss;

import java.security.SecureRandom;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Key pair generator for XMSS^MT keys.
 */
public final class XMSSMTKeyPairGenerator
{
    private XMSSMTParameters params;
    private XMSS xmss;
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
        xmss = params.getXMSS();
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


            /* init global xmss */
        XMSSPrivateKeyParameters xmssPrivateKey = new XMSSPrivateKeyParameters.Builder(xmss.getParams())
            .withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF())
            .withPublicSeed(privateKey.getPublicSeed()).withBDSState(new BDS(xmss)).build();
        XMSSPublicKeyParameters xmssPublicKey = new XMSSPublicKeyParameters.Builder(xmss.getParams()).withPublicSeed(privateKey.getPublicSeed())
            .build();

            /* import to xmss */
        xmss.importState(xmssPrivateKey, xmssPublicKey);

            /* get root */
        int rootLayerIndex = params.getLayers() - 1;
        OTSHashAddress otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withLayerAddress(rootLayerIndex)
            .build();

          		/* store BDS instance of root xmss instance */
        BDS bdsRoot = new BDS(xmss);
        XMSSNode root = bdsRoot.initialize(xmssPrivateKey, otsHashAddress);
        privateKey.getBDSState().put(rootLayerIndex, bdsRoot);
        xmss.setRoot(root.getValue());

            /* set XMSS^MT root / create public key */
        privateKey = new XMSSMTPrivateKeyParameters.Builder(params).withSecretKeySeed(privateKey.getSecretKeySeed())
            .withSecretKeyPRF(privateKey.getSecretKeyPRF()).withPublicSeed(privateKey.getPublicSeed())
            .withRoot(xmss.getRoot()).withBDSState(privateKey.getBDSState()).build();
        publicKey = new XMSSMTPublicKeyParameters.Builder(params).withRoot(root.getValue())
            .withPublicSeed(privateKey.getPublicSeed()).build();

        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }

    private XMSSMTPrivateKeyParameters generatePrivateKey(Map<Integer, BDS> bdsState)
    {
        int n = params.getDigestSize();
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
