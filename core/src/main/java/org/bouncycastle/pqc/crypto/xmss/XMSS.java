package org.bouncycastle.pqc.crypto.xmss;

import java.io.IOException;
import java.security.SecureRandom;
import java.text.ParseException;

/**
 * XMSS.
 *
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
     * BDS.
     */
    private BDS bdsState;

    /**
     * XMSS constructor...
     *
     * @param params XMSSParameters.
     */
    public XMSS(XMSSParameters params)
    {
        super();
        if (params == null)
        {
            throw new NullPointerException("params == null");
        }
        this.params = params;
        wotsPlus = params.getWOTSPlus();
        prng = params.getPRNG();
        khf = wotsPlus.getKhf();
        privateKey = new XMSSPrivateKeyParameters(params);
        publicKey = new XMSSPublicKeyParameters(params);
        bdsState = new BDS(this);
    }

    /**
     * Generate new keys.
     */
    public void generateKeys()
    {
        /* generate private key */
        privateKey = generatePrivateKey();
        wotsPlus.importKeys(new byte[params.getDigestSize()], privateKey.getPublicSeed());

        XMSSNode root = bdsState.initialize(new OTSHashAddress());
        privateKey.setRoot(root.getValue());
		
		/* generate public key */
        publicKey = new XMSSPublicKeyParameters(params);
        publicKey.setRoot(root.getValue());
        publicKey.setPublicSeed(getPublicSeed());
    }


    /**
     * Generate an XMSS private key.
     *
     * @return XMSS private key.
     */
    private XMSSPrivateKeyParameters generatePrivateKey()
    {
        int n = params.getDigestSize();
        byte[] publicSeed = new byte[n];
        prng.nextBytes(publicSeed);
        byte[] secretKeySeed = new byte[n];
        prng.nextBytes(secretKeySeed);
        byte[] secretKeyPRF = new byte[n];
        prng.nextBytes(secretKeyPRF);

        XMSSPrivateKeyParameters privateKey = new XMSSPrivateKeyParameters(params);
        privateKey.setPublicSeed(publicSeed);
        privateKey.setSecretKeySeed(secretKeySeed);
        privateKey.setSecretKeyPRF(secretKeyPRF);
        return privateKey;
    }

    /**
     * Import state.
     *
     * @param privateKey XMSS private key.
     * @param publicKey  XMSS public key.
     * @param bdsState   BDS state.
     * @throws IOException
     * @throws ClassNotFoundException
     */
    public void importState(byte[] privateKey, byte[] publicKey, byte[] bdsState)
        throws ParseException, ClassNotFoundException, IOException
    {
        if (privateKey == null)
        {
            throw new NullPointerException("privateKey == null");
        }
        if (publicKey == null)
        {
            throw new NullPointerException("publicKey == null");
        }
        if (bdsState == null)
        {
            throw new NullPointerException("bdsState == null");
        }
		/* import keys */
        importKeys(privateKey, publicKey);
		
		/* import BDS state */
        BDS bdsImport = (BDS)XMSSUtil.deserialize(bdsState);
        bdsImport.setXMSS(this);
        bdsImport.validate(true);
        this.bdsState = bdsImport;
    }

    protected void importKeys(byte[] privateKey, byte[] publicKey)
        throws ParseException
    {
        if (privateKey == null)
        {
            throw new NullPointerException("privateKey == null");
        }
        if (publicKey == null)
        {
            throw new NullPointerException("publicKey == null");
        }
		/* validate private / public key */
        XMSSPrivateKeyParameters tmpPrivateKey = new XMSSPrivateKeyParameters(params);
        tmpPrivateKey.parseByteArray(privateKey);
        XMSSPublicKeyParameters tmpPublicKey = new XMSSPublicKeyParameters(params);
        tmpPublicKey.parseByteArray(publicKey);
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
        if (bdsState.getAuthenticationPath().isEmpty())
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
        byte[] concatenated = XMSSUtil.concat(random, privateKey.getRoot(), XMSSUtil.toBytesBigEndian(index, params.getDigestSize()));
        byte[] messageDigest = khf.HMsg(concatenated, message);
		
		/* create signature for messageDigest */
        OTSHashAddress otsHashAddress = new OTSHashAddress();
        otsHashAddress.setOTSAddress(index);
        XMSSSignature signature = treeSig(messageDigest, otsHashAddress);
        signature.setIndex(index);
        signature.setRandom(random);
        signature.setAuthPath(bdsState.getAuthenticationPath());
		
		/* prepare authentication path for next leaf */
        int treeHeight = this.getParams().getHeight();
        if (index < ((1 << treeHeight) - 1))
        {
            bdsState.nextAuthenticationPath(new OTSHashAddress());
        }

		/* update index */
        privateKey.setIndex(index + 1);

        return signature.toByteArray();
    }

    /**
     * Verify an XMSS signature using the corresponding XMSS public key and a message.
     *
     * @param message   Message.
     * @param signature XMSS signature.
     * @param publicKey XMSS public key.
     * @return true if signature is valid false else.
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
		/* parse signature and public key */
        XMSSSignature sig = new XMSSSignature(params);
        sig.parseByteArray(signature);
        XMSSPublicKeyParameters pubKey = new XMSSPublicKeyParameters(params);
        pubKey.parseByteArray(publicKey);

		/* save state */
        int savedIndex = privateKey.getIndex();
        byte[] savedPublicSeed = privateKey.getPublicSeed();
		
		/* set index / public seed */
        int index = sig.getIndex();
        setIndex(index);
        setPublicSeed(pubKey.getPublicSeed());

		/* reinitialize WOTS+ object */
        wotsPlus.importKeys(new byte[params.getDigestSize()], getPublicSeed());
		
		/* create message digest */
        byte[] concatenated = XMSSUtil.concat(sig.getRandom(), pubKey.getRoot(), XMSSUtil.toBytesBigEndian(index, params.getDigestSize()));
        byte[] messageDigest = khf.HMsg(concatenated, message);
		
		/* create addresses */
        OTSHashAddress otsHashAddress = new OTSHashAddress();
        otsHashAddress.setOTSAddress(index);
		
		/* get root from signature */
        XMSSNode rootNodeFromSignature = getRootNodeFromSignature(messageDigest, sig, otsHashAddress);
		
		/* reset state */
        setIndex(savedIndex);
        setPublicSeed(savedPublicSeed);
        return XMSSUtil.compareByteArray(rootNodeFromSignature.getValue(), pubKey.getRoot());
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
     * Export XMSS BDS state.
     *
     * @return XMSS BDS state.
     * @throws IOException
     */
    public byte[] exportBDSState()
        throws IOException
    {
        return XMSSUtil.serialize(bdsState);
    }

    /**
     * Randomization of nodes in binary tree.
     *
     * @param left            Left node.
     * @param right           Right node.
     * @param hashTreeAddress Address.
     * @return Randomized hash of parent of left / right node.
     */
    protected XMSSNode randomizeHash(XMSSNode left, XMSSNode right, XMSSAddress address)
    {
        if (left == null)
        {
            throw new NullPointerException("left == null");
        }
        if (right == null)
        {
            throw new NullPointerException("right == null");
        }
        if (left.getHeight() != right.getHeight())
        {
            throw new IllegalStateException("height of both nodes must be equal");
        }
        if (address == null)
        {
            throw new NullPointerException("address == null");
        }
        byte[] publicSeed = getPublicSeed();
        address.setKeyAndMask(0);
        byte[] key = khf.PRF(publicSeed, address.toByteArray());
        address.setKeyAndMask(1);
        byte[] bitmask0 = khf.PRF(publicSeed, address.toByteArray());
        address.setKeyAndMask(2);
        byte[] bitmask1 = khf.PRF(publicSeed, address.toByteArray());
        int n = params.getDigestSize();
        byte[] tmpMask = new byte[2 * n];
        for (int i = 0; i < n; i++)
        {
            tmpMask[i] = (byte)(left.getValue()[i] ^ bitmask0[i]);
        }
        for (int i = 0; i < n; i++)
        {
            tmpMask[i + n] = (byte)(right.getValue()[i] ^ bitmask1[i]);
        }
        byte[] out = khf.H(key, tmpMask);
        return new XMSSNode(left.getHeight(), out);
    }

    /**
     * Compresses a WOTS+ public key to a single n-byte string.
     *
     * @param publicKey WOTS+ public key to compress.
     * @param address   Address.
     * @return Compressed n-byte string of public key.
     */
    protected XMSSNode lTree(WOTSPlusPublicKeyParameters publicKey, LTreeAddress address)
    {
        if (publicKey == null)
        {
            throw new NullPointerException("publicKey == null");
        }
        if (address == null)
        {
            throw new NullPointerException("address == null");
        }
        int len = wotsPlus.getParams().getLen();
		/* duplicate public key to XMSSNode Array */
        byte[][] publicKeyBytes = publicKey.toByteArray();
        XMSSNode[] publicKeyNodes = new XMSSNode[publicKeyBytes.length];
        for (int i = 0; i < publicKeyBytes.length; i++)
        {
            publicKeyNodes[i] = new XMSSNode(0, publicKeyBytes[i]);
        }
        address.setTreeHeight(0);
        while (len > 1)
        {
            for (int i = 0; i < (int)Math.floor(len / 2); i++)
            {
                address.setTreeIndex(i);
                publicKeyNodes[i] = randomizeHash(publicKeyNodes[2 * i], publicKeyNodes[(2 * i) + 1], address);
            }
            if (len % 2 == 1)
            {
                publicKeyNodes[(int)Math.floor(len / 2)] = publicKeyNodes[len - 1];
            }
            len = (int)Math.ceil((double)len / 2);
            address.setTreeHeight(address.getTreeHeight() + 1);
        }
        return publicKeyNodes[0];
    }

    /**
     * Generate a WOTS+ signature on a message without the corresponding authentication path
     *
     * @param messageDigest Message digest of length n.
     * @param address       OTS hash address.
     * @return XMSS signature.
     */
    protected XMSSSignature treeSig(byte[] messageDigest, OTSHashAddress otsHashAddress)
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
        WOTSPlusSignature wotsSignature = wotsPlus.sign(messageDigest, otsHashAddress);
		
		/* assemble temp signature */
        XMSSSignature tmpSignature = new XMSSSignature(params);
        tmpSignature.setSignature(wotsSignature);
        return tmpSignature;
    }


    /**
     * Compute a root node from a tree signature.
     *
     * @param messageDigest Message digest.
     * @param signature     XMSS signature.
     * @return Root node calculated from signature.
     */
    protected XMSSNode getRootNodeFromSignature(byte[] messageDigest, XMSSReducedSignature signature, OTSHashAddress otsHashAddress)
    {
        if (messageDigest.length != params.getDigestSize())
        {
            throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
        }
        if (signature == null)
        {
            throw new NullPointerException("signature == null");
        }
        if (otsHashAddress == null)
        {
            throw new NullPointerException("otsHashAddress == null");
        }
		
		/* prepare adresses */
        LTreeAddress lTreeAddress = new LTreeAddress();
        lTreeAddress.setLayerAddress(otsHashAddress.getLayerAddress());
        lTreeAddress.setTreeAddress(otsHashAddress.getTreeAddress());
        lTreeAddress.setLTreeAddress(otsHashAddress.getOTSAddress());
        HashTreeAddress hashTreeAddress = new HashTreeAddress();
        hashTreeAddress.setLayerAddress(otsHashAddress.getLayerAddress());
        hashTreeAddress.setTreeAddress(otsHashAddress.getTreeAddress());
        hashTreeAddress.setTreeIndex(otsHashAddress.getOTSAddress());
		
		/* calculate WOTS+ public key and compress to obtain original leaf hash */
        WOTSPlusPublicKeyParameters wotsPlusPK = wotsPlus.getPublicKeyFromSignature(messageDigest, signature.getSignature(), otsHashAddress);
        XMSSNode[] node = new XMSSNode[2];
        node[0] = lTree(wotsPlusPK, lTreeAddress);

        for (int k = 0; k < params.getHeight(); k++)
        {
            hashTreeAddress.setTreeHeight(k);
            if (Math.floor(privateKey.getIndex() / (1 << k)) % 2 == 0)
            {
                hashTreeAddress.setTreeIndex(hashTreeAddress.getTreeIndex() / 2);
                node[1] = randomizeHash(node[0], signature.getAuthPath().get(k), hashTreeAddress);
                node[1].setHeight(node[1].getHeight() + 1);
            }
            else
            {
                hashTreeAddress.setTreeIndex((hashTreeAddress.getTreeIndex() - 1) / 2);
                node[1] = randomizeHash(signature.getAuthPath().get(k), node[0], hashTreeAddress);
                node[1].setHeight(node[1].getHeight() + 1);
            }
            node[0] = node[1];
        }
        return node[0];
    }

    /**
     * Derive WOTS+ secret key for specific index according to draft.
     * @param index Index.
     * @return WOTS+ secret key at index.
     */
	/*
	protected byte[] getWOTSPlusSecretKey(int index) {
		return khf.PRF(privateKey.getSecretKeySeed(), XMSSUtil.toBytesBigEndian(index, 32));
	}
	*/

    /**
     * Derive WOTS+ secret key for specific index as in XMSS ref impl Andreas Huelsing.
     *
     * @param index Index.
     * @return WOTS+ secret key at index.
     */
    protected byte[] getWOTSPlusSecretKey(OTSHashAddress otsHashAddress)
    {
        otsHashAddress.setChainAddress(0);
        otsHashAddress.setHashAddress(0);
        otsHashAddress.setKeyAndMask(0);
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
     * Getter Root.
     *
     * @return Root of binary tree.
     */
    protected byte[] getRoot()
    {
        return privateKey.getRoot();
    }

    protected void setRoot(byte[] root)
    {
        privateKey.setRoot(root);
        publicKey.setRoot(root);
    }

    /**
     * Getter index.
     *
     * @return Index.
     */
    public int getIndex()
    {
        return privateKey.getIndex();
    }

    protected void setIndex(int index)
    {
        privateKey.setIndex(index);
    }

    /**
     * Getter public seed.
     *
     * @return Public seed.
     */
    protected byte[] getPublicSeed()
    {
        return privateKey.getPublicSeed();
    }

    protected void setPublicSeed(byte[] publicSeed)
    {
        privateKey.setPublicSeed(publicSeed);
        publicKey.setPublicSeed(publicSeed);
        wotsPlus.importKeys(new byte[params.getDigestSize()], publicSeed);
    }

    protected BDS getBDS()
    {
        return bdsState;
    }
}
