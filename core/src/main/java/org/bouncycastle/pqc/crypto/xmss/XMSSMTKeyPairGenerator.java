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
    private XMSSParameters xmssParams;
    
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
        this.xmssParams = xmss.getParams();
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
        XMSSPrivateKeyParameters xmssPrivateKey = new XMSSPrivateKeyParameters.Builder(xmssParams)
            .withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF())
            .withPublicSeed(privateKey.getPublicSeed()).withBDSState(new BDS(xmssParams)).build();
        XMSSPublicKeyParameters xmssPublicKey = new XMSSPublicKeyParameters.Builder(xmssParams).withPublicSeed(privateKey.getPublicSeed())
            .build();

            /* import to xmss */
        xmss.importState(xmssPrivateKey, xmssPublicKey);
        xmssParams.getWOTSPlus().importKeys(new byte[params.getDigestSize()], xmssPrivateKey.getPublicSeed());

            /* get root */
        int rootLayerIndex = params.getLayers() - 1;
        OTSHashAddress otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withLayerAddress(rootLayerIndex)
            .build();

          		/* store BDS instance of root xmss instance */
        BDS bdsRoot = new BDS(xmssParams, xmssPrivateKey.getPublicSeed(), xmssPrivateKey.getSecretKeySeed(), otsHashAddress);
        XMSSNode root = bdsRoot.getRoot();
        privateKey.getBDSState().put(rootLayerIndex, bdsRoot);
        xmss.setRoot(root.getValue());

            /* set XMSS^MT root / create public key */
        privateKey = new XMSSMTPrivateKeyParameters.Builder(params).withSecretKeySeed(privateKey.getSecretKeySeed())
            .withSecretKeyPRF(privateKey.getSecretKeyPRF()).withPublicSeed(privateKey.getPublicSeed())
            .withRoot(root.getValue()).withBDSState(privateKey.getBDSState()).build();
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
