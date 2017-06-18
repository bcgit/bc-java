package org.bouncycastle.pqc.crypto.xmss;

import java.io.IOException;
import java.security.SecureRandom;
import java.text.ParseException;

/**
 * XMSS.
 */
public class XMSS
{

    /**
     * XMSS parameters.
     */
    private XMSSParameters params;
    /**
     * WOTS+ instance.
     */
    private WOTSPlus wotsPlus;
    /**
     * PRNG.
     */
    private SecureRandom prng;
    /**
     * Randomization functions.
     */
    private KeyedHashFunctions khf;
    /**
     * XMSS private key.
     */
    private XMSSPrivateKeyParameters privateKey;
    /**
     * XMSS public key.
     */
    private XMSSPublicKeyParameters publicKey;

    /**
     * XMSS constructor...
     *
     * @param params XMSSParameters.
     */
    public XMSS(XMSSParameters params, SecureRandom prng)
    {
        super();
        if (params == null)
        {
            throw new NullPointerException("params == null");
        }
        this.params = params;
        wotsPlus = params.getWOTSPlus();
        this.prng = prng;
        khf = wotsPlus.getKhf();

        privateKey = new XMSSPrivateKeyParameters.Builder(params).withBDSState(new BDS(this)).build();
        publicKey = new XMSSPublicKeyParameters.Builder(params).build();
    }

    /**
     * Generate a new XMSS private key / public key pair.
     */
    public void generateKeys()
    {
        /* generate private key */
        privateKey = generatePrivateKey();
        XMSSNode root = getBDSState().initialize((OTSHashAddress)new OTSHashAddress.Builder().build());

        privateKey = new XMSSPrivateKeyParameters.Builder(params).withIndex(privateKey.getIndex())
            .withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF())
            .withPublicSeed(privateKey.getPublicSeed()).withRoot(root.getValue())
            .withBDSState(privateKey.getBDSState()).build();
        publicKey = new XMSSPublicKeyParameters.Builder(params).withRoot(root.getValue())
            .withPublicSeed(getPublicSeed()).build();

    }

    /**
     * Generate an XMSS private key.
     *
     * @return XMSS private key.
     */
    private XMSSPrivateKeyParameters generatePrivateKey()
    {
        int n = params.getDigestSize();
        byte[] secretKeySeed = new byte[n];
        prng.nextBytes(secretKeySeed);
        byte[] secretKeyPRF = new byte[n];
        prng.nextBytes(secretKeyPRF);
        byte[] publicSeed = new byte[n];
        prng.nextBytes(publicSeed);

        XMSSPrivateKeyParameters privateKey = new XMSSPrivateKeyParameters.Builder(params).withSecretKeySeed(secretKeySeed)
            .withSecretKeyPRF(secretKeyPRF).withPublicSeed(publicSeed)
            .withBDSState(this.privateKey.getBDSState()).build();

        return privateKey;
    }

    void importState(XMSSPrivateKeyParameters privateKey, XMSSPublicKeyParameters publicKey)
    {
        /* import */
        this.privateKey = privateKey;
        this.publicKey = publicKey;

        wotsPlus.importKeys(new byte[params.getDigestSize()], this.privateKey.getPublicSeed());
    }

    /**
     * Import XMSS private key / public key pair.
     *
     * @param privateKey XMSS private key.
     * @param publicKey  XMSS public key.
     * @throws ClassNotFoundException
     * @throws IOException
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
		/* import keys */
        XMSSPrivateKeyParameters tmpPrivateKey = new XMSSPrivateKeyParameters.Builder(params)
            .withPrivateKey(privateKey, this).build();
        XMSSPublicKeyParameters tmpPublicKey = new XMSSPublicKeyParameters.Builder(params).withPublicKey(publicKey)
            .build();
        if (!XMSSUtil.compareByteArray(tmpPrivateKey.getRoot(), tmpPublicKey.getRoot()))
        {
            throw new IllegalStateException("root of private key and public key do not match");
        }
        if (!XMSSUtil.compareByteArray(tmpPrivateKey.getPublicSeed(), tmpPublicKey.getPublicSeed()))
        {
            throw new IllegalStateException("public seed of private key and public key do not match");
        }
		/* import */
        this.privateKey = tmpPrivateKey;
        this.publicKey = tmpPublicKey;
        wotsPlus.importKeys(new byte[params.getDigestSize()], this.privateKey.getPublicSeed());
    }

    /**
     * Sign message.
     *
     * @param message Message to sign.
     * @return XMSS signature on digest of message.
     */
    public byte[] sign(byte[] message)
    {
        if (message == null)
        {
            throw new NullPointerException("message == null");
        }
        if (getBDSState().getAuthenticationPath().isEmpty())
        {
            throw new IllegalStateException("not initialized");
        }
        int index = privateKey.getIndex();
        if (!XMSSUtil.isIndexValid(getParams().getHeight(), index))
        {
            throw new IllegalArgumentException("index out of bounds");
        }

		/* create (randomized keyed) messageDigest of message */
        byte[] random = khf.PRF(privateKey.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian(index, 32));
        byte[] concatenated = XMSSUtil.concat(random, privateKey.getRoot(),
            XMSSUtil.toBytesBigEndian(index, params.getDigestSize()));
        byte[] messageDigest = khf.HMsg(concatenated, message);

		/* create signature for messageDigest */
        OTSHashAddress otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withOTSAddress(index).build();
        WOTSPlusSignature wotsPlusSignature = wotsSign(messageDigest, otsHashAddress);
        XMSSSignature signature = (XMSSSignature)new XMSSSignature.Builder(params).withIndex(index).withRandom(random)
            .withWOTSPlusSignature(wotsPlusSignature).withAuthPath(getBDSState().getAuthenticationPath())
            .build();


		/* prepare authentication path for next leaf */
        int treeHeight = this.getParams().getHeight();
        if (index < ((1 << treeHeight) - 1))
        {
            getBDSState().nextAuthenticationPath((OTSHashAddress)new OTSHashAddress.Builder().build());
        }

		/* update index */
        setIndex(index + 1);

        return signature.toByteArray();
    }

    /**
     * Verify an XMSS signature.
     *
     * @param message   Message.
     * @param signature XMSS signature.
     * @param publicKey XMSS public key.
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

        XMSSSigner signer = new XMSSSigner();

        signer.init(false, new XMSSPublicKeyParameters.Builder(getParams()).withPublicKey(publicKey).build());

        return signer.verifySignature(message, signature);
    }

    /**
     * Export XMSS private key.
     *
     * @return XMSS private key.
     */
    public byte[] exportPrivateKey()
    {
        return privateKey.toByteArray();
    }

    /**
     * Export XMSS public key.
     *
     * @return XMSS public key.
     */
    public byte[] exportPublicKey()
    {
        return publicKey.toByteArray();
    }

    /**
     * Generate a WOTS+ signature on a message without the corresponding
     * authentication path
     *
     * @param messageDigest  Message digest of length n.
     * @param otsHashAddress OTS hash address.
     * @return XMSS signature.
     */
    protected WOTSPlusSignature wotsSign(byte[] messageDigest, OTSHashAddress otsHashAddress)
    {
        if (messageDigest.length != params.getDigestSize())
        {
            throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
        }
        if (otsHashAddress == null)
        {
            throw new NullPointerException("otsHashAddress == null");
        }
		/* (re)initialize WOTS+ instance */
        wotsPlus.importKeys(getWOTSPlusSecretKey(otsHashAddress), getPublicSeed());
		/* create WOTS+ signature */
        return wotsPlus.sign(messageDigest, otsHashAddress);
    }

    /**
     * Derive WOTS+ secret key for specific index as in XMSS ref impl Andreas
     * Huelsing.
     *
     * @param otsHashAddress
     * @return WOTS+ secret key at index.
     */
    protected byte[] getWOTSPlusSecretKey(OTSHashAddress otsHashAddress)
    {
        otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .withOTSAddress(otsHashAddress.getOTSAddress()).build();
        return khf.PRF(privateKey.getSecretKeySeed(), otsHashAddress.toByteArray());
    }

    /**
     * Getter XMSS params.
     *
     * @return XMSS params.
     */
    public XMSSParameters getParams()
    {
        return params;
    }

    /**
     * Getter WOTS+.
     *
     * @return WOTS+ instance.
     */
    protected WOTSPlus getWOTSPlus()
    {
        return wotsPlus;
    }

    protected KeyedHashFunctions getKhf()
    {
        return khf;
    }

    /**
     * Getter XMSS root.
     *
     * @return Root of binary tree.
     */
    public byte[] getRoot()
    {
        return privateKey.getRoot();
    }

    protected void setRoot(byte[] root)
    {
        privateKey = new XMSSPrivateKeyParameters.Builder(params).withIndex(privateKey.getIndex())
            .withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF())
            .withPublicSeed(getPublicSeed()).withRoot(root).withBDSState(privateKey.getBDSState()).build();
        publicKey = new XMSSPublicKeyParameters.Builder(params).withRoot(root).withPublicSeed(getPublicSeed())
            .build();
    }

    /**
     * Getter XMSS index.
     *
     * @return Index.
     */
    public int getIndex()
    {
        return privateKey.getIndex();
    }

    protected void setIndex(int index)
    {
        privateKey = new XMSSPrivateKeyParameters.Builder(params).withIndex(index)
            .withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF())
            .withPublicSeed(privateKey.getPublicSeed()).withRoot(privateKey.getRoot())
            .withBDSState(privateKey.getBDSState()).build();
    }

    /**
     * Getter XMSS public seed.
     *
     * @return Public seed.
     */
    public byte[] getPublicSeed()
    {
        return privateKey.getPublicSeed();
    }

    protected void setPublicSeed(byte[] publicSeed)
    {
        privateKey = new XMSSPrivateKeyParameters.Builder(params).withIndex(privateKey.getIndex())
            .withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF())
            .withPublicSeed(publicSeed).withRoot(getRoot()).withBDSState(privateKey.getBDSState()).build();
        publicKey = new XMSSPublicKeyParameters.Builder(params).withRoot(getRoot()).withPublicSeed(publicSeed)
            .build();

        wotsPlus.importKeys(new byte[params.getDigestSize()], publicSeed);
    }

    protected BDS getBDSState()
    {
        return privateKey.getBDSState();
    }
}
