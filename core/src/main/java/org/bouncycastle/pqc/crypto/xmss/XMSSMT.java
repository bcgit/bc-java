package org.bouncycastle.pqc.crypto.xmss;

import java.security.SecureRandom;
import java.text.ParseException;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.util.Arrays;

/**
 * XMSS^MT.
 */
public final class XMSSMT
{

    private XMSSMTParameters params;
    private XMSSParameters xmssParams;
    private SecureRandom prng;
    private XMSSMTPrivateKeyParameters privateKey;
    private XMSSMTPublicKeyParameters publicKey;

    /**
     * XMSSMT constructor...
     *
     * @param params XMSSMTParameters.
     */
    public XMSSMT(XMSSMTParameters params, SecureRandom prng)
    {
        super();
        if (params == null)
        {
            throw new NullPointerException("params == null");
        }
        this.params = params;
        xmssParams = params.getXMSSParameters();
        this.prng = prng;

        privateKey = new XMSSMTPrivateKeyParameters.Builder(params).build();
        publicKey = new XMSSMTPublicKeyParameters.Builder(params).build();
    }

    /**
     * Generate a new XMSSMT private key / public key pair.
     */
    public void generateKeys()
    {
        XMSSMTKeyPairGenerator kpGen = new XMSSMTKeyPairGenerator();

        kpGen.init(new XMSSMTKeyGenerationParameters(getParams(), prng));

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        privateKey = (XMSSMTPrivateKeyParameters)kp.getPrivate();
        publicKey = (XMSSMTPublicKeyParameters)kp.getPublic();

        importState(privateKey, publicKey);
    }

    private void importState(XMSSMTPrivateKeyParameters privateKey, XMSSMTPublicKeyParameters publicKey)
    {
		/* import to xmss */
        xmssParams.getWOTSPlus().importKeys(new byte[params.getTreeDigestSize()], this.privateKey.getPublicSeed());

        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * Import XMSSMT private key / public key pair.
     *
     * @param privateKey XMSSMT private key.
     * @param publicKey  XMSSMT public key.
     */
    public void importState(byte[] privateKey, byte[] publicKey)
    {
        if (privateKey == null)
        {
            throw new NullPointerException("privateKey == null");
        }
        if (publicKey == null)
        {
            throw new NullPointerException("publicKey == null");
        }
        XMSSMTPrivateKeyParameters xmssMTPrivateKey = new XMSSMTPrivateKeyParameters.Builder(params)
            .withPrivateKey(privateKey).build();
        XMSSMTPublicKeyParameters xmssMTPublicKey = new XMSSMTPublicKeyParameters.Builder(params)
            .withPublicKey(publicKey).build();
        if (!Arrays.areEqual(xmssMTPrivateKey.getRoot(), xmssMTPublicKey.getRoot()))
        {
            throw new IllegalStateException("root of private key and public key do not match");
        }
        if (!Arrays.areEqual(xmssMTPrivateKey.getPublicSeed(), xmssMTPublicKey.getPublicSeed()))
        {
            throw new IllegalStateException("public seed of private key and public key do not match");
        }
        
		/* import to xmss */
        xmssParams.getWOTSPlus().importKeys(new byte[params.getTreeDigestSize()], xmssMTPrivateKey.getPublicSeed());

        this.privateKey = xmssMTPrivateKey;
        this.publicKey = xmssMTPublicKey;
    }

    /**
     * Sign message.
     *
     * @param message Message to sign.
     * @return XMSSMT signature on digest of message.
     */
    public byte[] sign(byte[] message)
    {
        if (message == null)
        {
            throw new NullPointerException("message == null");
        }

        XMSSMTSigner signer = new XMSSMTSigner();

        signer.init(true, privateKey);

        byte[] signature = signer.generateSignature(message);

        privateKey = (XMSSMTPrivateKeyParameters)signer.getUpdatedPrivateKey();

        importState(privateKey, publicKey);

        return signature;
    }

    /**
     * Verify an XMSSMT signature.
     *
     * @param message   Message.
     * @param signature XMSSMT signature.
     * @param publicKey XMSSMT public key.
     * @return true if signature is valid false else.
     * @throws ParseException
     */
    public boolean verifySignature(byte[] message, byte[] signature, byte[] publicKey)
        throws ParseException
    {
        if (message == null)
        {
            throw new NullPointerException("message == null");
        }
        if (signature == null)
        {
            throw new NullPointerException("signature == null");
        }
        if (publicKey == null)
        {
            throw new NullPointerException("publicKey == null");
        }

        XMSSMTSigner signer = new XMSSMTSigner();

        signer.init(false, new XMSSMTPublicKeyParameters.Builder(getParams()).withPublicKey(publicKey).build());

        return signer.verifySignature(message, signature);
    }

    /**
     * Export XMSSMT private key.
     *
     * @return XMSSMT private key.
     */
    public byte[] exportPrivateKey()
    {
        return privateKey.toByteArray();
    }

    /**
     * Export XMSSMT public key.
     *
     * @return XMSSMT public key.
     */
    public byte[] exportPublicKey()
    {
        return publicKey.toByteArray();
    }

    /**
     * Getter XMSSMT params.
     *
     * @return XMSSMT params.
     */
    public XMSSMTParameters getParams()
    {
        return params;
    }


    /**
     * Getter public seed.
     *
     * @return Public seed.
     */
    public byte[] getPublicSeed()
    {
        return privateKey.getPublicSeed();
    }

    protected XMSSParameters getXMSS()
    {
        return xmssParams;
    }
}
