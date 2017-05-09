package org.bouncycastle.pqc.crypto.xmss;

import java.io.IOException;
import java.security.SecureRandom;
import java.text.ParseException;

/**
 * XMSS.
 *
 */
public class XMSS {

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
	 * @param params
	 *            XMSSParameters.
	 */
	public XMSS(XMSSParameters params) {
		super();
		if (params == null) {
			throw new NullPointerException("params == null");
		}
		this.params = params;
		wotsPlus = params.getWOTSPlus();
		prng = params.getPRNG();
		khf = wotsPlus.getKhf();
		try {
			privateKey = new XMSSPrivateKeyParameters.Builder(params).withBDSState(new BDS(this)).build();
			publicKey = new XMSSPublicKeyParameters.Builder(params).build();
		} catch (ParseException e) {
			/* should not be possible */
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			/* should not be possible */
			e.printStackTrace();
		} catch (IOException e) {
			/* should not be possible */
			e.printStackTrace();
		}
	}

	/**
	 * Generate a new XMSS private key / public key pair.
	 * 
	 */
	public void generateKeys() {
		/* generate private key */
		privateKey = generatePrivateKey();
		XMSSNode root = getBDSState().initialize((OTSHashAddress) new OTSHashAddress.Builder().build());
		try {
			privateKey = new XMSSPrivateKeyParameters.Builder(params).withIndex(privateKey.getIndex())
					.withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF())
					.withPublicSeed(privateKey.getPublicSeed()).withRoot(root.getValue())
					.withBDSState(privateKey.getBDSState()).build();
			publicKey = new XMSSPublicKeyParameters.Builder(params).withRoot(root.getValue())
					.withPublicSeed(getPublicSeed()).build();
		} catch (ParseException ex) {
			/* should not be possible */
			ex.printStackTrace();
		} catch (ClassNotFoundException e) {
			/* should not be possible */
			e.printStackTrace();
		} catch (IOException e) {
			/* should not be possible */
			e.printStackTrace();
		}
	}

	/**
	 * Generate an XMSS private key.
	 *
	 * @return XMSS private key.
	 */
	private XMSSPrivateKeyParameters generatePrivateKey() {
		int n = params.getDigestSize();
		byte[] secretKeySeed = new byte[n];
		prng.nextBytes(secretKeySeed);
		byte[] secretKeyPRF = new byte[n];
		prng.nextBytes(secretKeyPRF);
		byte[] publicSeed = new byte[n];
		prng.nextBytes(publicSeed);

		XMSSPrivateKeyParameters privateKey = null;
		try {
			privateKey = new XMSSPrivateKeyParameters.Builder(params).withSecretKeySeed(secretKeySeed)
					.withSecretKeyPRF(secretKeyPRF).withPublicSeed(publicSeed)
					.withBDSState(this.privateKey.getBDSState()).build();
		} catch (ParseException e) {
			/* should not be possible */
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			/* should not be possible */
			e.printStackTrace();
		} catch (IOException e) {
			/* should not be possible */
			e.printStackTrace();
		}
		return privateKey;
	}

	/**
	 * Import XMSS private key / public key pair.
	 * 
	 * @param privateKey
	 *            XMSS private key.
	 * @param publicKey
	 *            XMSS public key.
	 * @throws ParseException
	 * @throws ClassNotFoundException
	 * @throws IOException
	 */
	public void importState(byte[] privateKey, byte[] publicKey)
			throws ParseException, ClassNotFoundException, IOException {
		if (privateKey == null) {
			throw new NullPointerException("privateKey == null");
		}
		if (publicKey == null) {
			throw new NullPointerException("publicKey == null");
		}
		/* import keys */
		XMSSPrivateKeyParameters tmpPrivateKey = new XMSSPrivateKeyParameters.Builder(params)
				.withPrivateKey(privateKey, this).build();
		XMSSPublicKeyParameters tmpPublicKey = new XMSSPublicKeyParameters.Builder(params).withPublicKey(publicKey)
				.build();
		if (!XMSSUtil.compareByteArray(tmpPrivateKey.getRoot(), tmpPublicKey.getRoot())) {
			throw new IllegalStateException("root of private key and public key do not match");
		}
		if (!XMSSUtil.compareByteArray(tmpPrivateKey.getPublicSeed(), tmpPublicKey.getPublicSeed())) {
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
	 * @param message
	 *            Message to sign.
	 * @return XMSS signature on digest of message.
	 */
	public byte[] sign(byte[] message) {
		if (message == null) {
			throw new NullPointerException("message == null");
		}
		if (getBDSState().getAuthenticationPath().isEmpty()) {
			throw new IllegalStateException("not initialized");
		}
		int index = privateKey.getIndex();
		if (!XMSSUtil.isIndexValid(getParams().getHeight(), index)) {
			throw new IllegalArgumentException("index out of bounds");
		}

		/* create (randomized keyed) messageDigest of message */
		byte[] random = khf.PRF(privateKey.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian(index, 32));
		byte[] concatenated = XMSSUtil.concat(random, privateKey.getRoot(),
				XMSSUtil.toBytesBigEndian(index, params.getDigestSize()));
		byte[] messageDigest = khf.HMsg(concatenated, message);

		/* create signature for messageDigest */
		OTSHashAddress otsHashAddress = (OTSHashAddress) new OTSHashAddress.Builder().withOTSAddress(index).build();
		WOTSPlusSignature wotsPlusSignature = wotsSign(messageDigest, otsHashAddress);
		XMSSSignature signature = null;
		try {
			signature = (XMSSSignature) new XMSSSignature.Builder(params).withIndex(index).withRandom(random)
					.withWOTSPlusSignature(wotsPlusSignature).withAuthPath(getBDSState().getAuthenticationPath())
					.build();
		} catch (ParseException ex) {
			/* should not happen */
			ex.printStackTrace();
		}

		/* prepare authentication path for next leaf */
		int treeHeight = this.getParams().getHeight();
		if (index < ((1 << treeHeight) - 1)) {
			getBDSState().nextAuthenticationPath((OTSHashAddress) new OTSHashAddress.Builder().build());
		}

		/* update index */
		setIndex(index + 1);

		return signature.toByteArray();
	}

	/**
	 * Verify an XMSS signature.
	 * 
	 * @param message
	 *            Message.
	 * @param signature
	 *            XMSS signature.
	 * @param publicKey
	 *            XMSS public key.
	 * @return true if signature is valid false else.
	 * @throws ParseException
	 */
	public boolean verifySignature(byte[] message, byte[] signature, byte[] publicKey) throws ParseException {
		if (message == null) {
			throw new NullPointerException("message == null");
		}
		if (signature == null) {
			throw new NullPointerException("signature == null");
		}
		if (publicKey == null) {
			throw new NullPointerException("publicKey == null");
		}
		/* parse signature and public key */
		XMSSSignature sig = new XMSSSignature.Builder(params).withSignature(signature).build();
		/* generate public key */
		XMSSPublicKeyParameters pubKey = new XMSSPublicKeyParameters.Builder(params).withPublicKey(publicKey).build();

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
		byte[] concatenated = XMSSUtil.concat(sig.getRandom(), pubKey.getRoot(),
				XMSSUtil.toBytesBigEndian(index, params.getDigestSize()));
		byte[] messageDigest = khf.HMsg(concatenated, message);

		/* get root from signature */
		OTSHashAddress otsHashAddress = (OTSHashAddress) new OTSHashAddress.Builder().withOTSAddress(index).build();
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
	public byte[] exportPrivateKey() {
		return privateKey.toByteArray();
	}

	/**
	 * Export XMSS public key.
	 *
	 * @return XMSS public key.
	 */
	public byte[] exportPublicKey() {
		return publicKey.toByteArray();
	}

	/**
	 * Randomization of nodes in binary tree.
	 *
	 * @param left
	 *            Left node.
	 * @param right
	 *            Right node.
	 * @param address
	 *            Address.
	 * @return Randomized hash of parent of left / right node.
	 */
	protected XMSSNode randomizeHash(XMSSNode left, XMSSNode right, XMSSAddress address) {
		if (left == null) {
			throw new NullPointerException("left == null");
		}
		if (right == null) {
			throw new NullPointerException("right == null");
		}
		if (left.getHeight() != right.getHeight()) {
			throw new IllegalStateException("height of both nodes must be equal");
		}
		if (address == null) {
			throw new NullPointerException("address == null");
		}
		byte[] publicSeed = getPublicSeed();

		if (address instanceof LTreeAddress) {
			LTreeAddress tmpAddress = (LTreeAddress) address;
			address = (LTreeAddress) new LTreeAddress.Builder().withLayerAddress(tmpAddress.getLayerAddress())
					.withTreeAddress(tmpAddress.getTreeAddress()).withLTreeAddress(tmpAddress.getLTreeAddress())
					.withTreeHeight(tmpAddress.getTreeHeight()).withTreeIndex(tmpAddress.getTreeIndex())
					.withKeyAndMask(0).build();
		} else if (address instanceof HashTreeAddress) {
			HashTreeAddress tmpAddress = (HashTreeAddress) address;
			address = (HashTreeAddress) new HashTreeAddress.Builder().withLayerAddress(tmpAddress.getLayerAddress())
					.withTreeAddress(tmpAddress.getTreeAddress()).withTreeHeight(tmpAddress.getTreeHeight())
					.withTreeIndex(tmpAddress.getTreeIndex()).withKeyAndMask(0).build();
		}

		byte[] key = khf.PRF(publicSeed, address.toByteArray());

		if (address instanceof LTreeAddress) {
			LTreeAddress tmpAddress = (LTreeAddress) address;
			address = (LTreeAddress) new LTreeAddress.Builder().withLayerAddress(tmpAddress.getLayerAddress())
					.withTreeAddress(tmpAddress.getTreeAddress()).withLTreeAddress(tmpAddress.getLTreeAddress())
					.withTreeHeight(tmpAddress.getTreeHeight()).withTreeIndex(tmpAddress.getTreeIndex())
					.withKeyAndMask(1).build();
		} else if (address instanceof HashTreeAddress) {
			HashTreeAddress tmpAddress = (HashTreeAddress) address;
			address = (HashTreeAddress) new HashTreeAddress.Builder().withLayerAddress(tmpAddress.getLayerAddress())
					.withTreeAddress(tmpAddress.getTreeAddress()).withTreeHeight(tmpAddress.getTreeHeight())
					.withTreeIndex(tmpAddress.getTreeIndex()).withKeyAndMask(1).build();
		}

		byte[] bitmask0 = khf.PRF(publicSeed, address.toByteArray());

		if (address instanceof LTreeAddress) {
			LTreeAddress tmpAddress = (LTreeAddress) address;
			address = (LTreeAddress) new LTreeAddress.Builder().withLayerAddress(tmpAddress.getLayerAddress())
					.withTreeAddress(tmpAddress.getTreeAddress()).withLTreeAddress(tmpAddress.getLTreeAddress())
					.withTreeHeight(tmpAddress.getTreeHeight()).withTreeIndex(tmpAddress.getTreeIndex())
					.withKeyAndMask(2).build();
		} else if (address instanceof HashTreeAddress) {
			HashTreeAddress tmpAddress = (HashTreeAddress) address;
			address = (HashTreeAddress) new HashTreeAddress.Builder().withLayerAddress(tmpAddress.getLayerAddress())
					.withTreeAddress(tmpAddress.getTreeAddress()).withTreeHeight(tmpAddress.getTreeHeight())
					.withTreeIndex(tmpAddress.getTreeIndex()).withKeyAndMask(2).build();
		}

		byte[] bitmask1 = khf.PRF(publicSeed, address.toByteArray());
		int n = params.getDigestSize();
		byte[] tmpMask = new byte[2 * n];
		for (int i = 0; i < n; i++) {
			tmpMask[i] = (byte) (left.getValue()[i] ^ bitmask0[i]);
		}
		for (int i = 0; i < n; i++) {
			tmpMask[i + n] = (byte) (right.getValue()[i] ^ bitmask1[i]);
		}
		byte[] out = khf.H(key, tmpMask);
		return new XMSSNode(left.getHeight(), out);
	}

	/**
	 * Compresses a WOTS+ public key to a single n-byte string.
	 *
	 * @param publicKey
	 *            WOTS+ public key to compress.
	 * @param address
	 *            Address.
	 * @return Compressed n-byte string of public key.
	 */
	protected XMSSNode lTree(WOTSPlusPublicKeyParameters publicKey, LTreeAddress address) {
		if (publicKey == null) {
			throw new NullPointerException("publicKey == null");
		}
		if (address == null) {
			throw new NullPointerException("address == null");
		}
		int len = wotsPlus.getParams().getLen();
		/* duplicate public key to XMSSNode Array */
		byte[][] publicKeyBytes = publicKey.toByteArray();
		XMSSNode[] publicKeyNodes = new XMSSNode[publicKeyBytes.length];
		for (int i = 0; i < publicKeyBytes.length; i++) {
			publicKeyNodes[i] = new XMSSNode(0, publicKeyBytes[i]);
		}
		address = (LTreeAddress) new LTreeAddress.Builder().withLayerAddress(address.getLayerAddress())
				.withTreeAddress(address.getTreeAddress()).withLTreeAddress(address.getLTreeAddress()).withTreeHeight(0)
				.withTreeIndex(address.getTreeIndex()).withKeyAndMask(address.getKeyAndMask()).build();
		while (len > 1) {
			for (int i = 0; i < (int) Math.floor(len / 2); i++) {
				address = (LTreeAddress) new LTreeAddress.Builder().withLayerAddress(address.getLayerAddress())
						.withTreeAddress(address.getTreeAddress()).withLTreeAddress(address.getLTreeAddress())
						.withTreeHeight(address.getTreeHeight()).withTreeIndex(i)
						.withKeyAndMask(address.getKeyAndMask()).build();
				publicKeyNodes[i] = randomizeHash(publicKeyNodes[2 * i], publicKeyNodes[(2 * i) + 1], address);
			}
			if (len % 2 == 1) {
				publicKeyNodes[(int) Math.floor(len / 2)] = publicKeyNodes[len - 1];
			}
			len = (int) Math.ceil((double) len / 2);
			address = (LTreeAddress) new LTreeAddress.Builder().withLayerAddress(address.getLayerAddress())
					.withTreeAddress(address.getTreeAddress()).withLTreeAddress(address.getLTreeAddress())
					.withTreeHeight(address.getTreeHeight() + 1).withTreeIndex(address.getTreeIndex())
					.withKeyAndMask(address.getKeyAndMask()).build();
		}
		return publicKeyNodes[0];
	}

	/**
	 * Generate a WOTS+ signature on a message without the corresponding
	 * authentication path
	 *
	 * @param messageDigest
	 *            Message digest of length n.
	 * @param otsHashAddress
	 *            OTS hash address.
	 * @return XMSS signature.
	 */
	protected WOTSPlusSignature wotsSign(byte[] messageDigest, OTSHashAddress otsHashAddress) {
		if (messageDigest.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
		}
		if (otsHashAddress == null) {
			throw new NullPointerException("otsHashAddress == null");
		}
		/* (re)initialize WOTS+ instance */
		wotsPlus.importKeys(getWOTSPlusSecretKey(otsHashAddress), getPublicSeed());
		/* create WOTS+ signature */
		return wotsPlus.sign(messageDigest, otsHashAddress);
	}

	/**
	 * Compute a root node from a tree signature.
	 *
	 * @param messageDigest
	 *            Message digest.
	 * @param signature
	 *            XMSS signature.
	 * @return Root node calculated from signature.
	 */
	protected XMSSNode getRootNodeFromSignature(byte[] messageDigest, XMSSReducedSignature signature,
			OTSHashAddress otsHashAddress) {
		if (messageDigest.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
		}
		if (signature == null) {
			throw new NullPointerException("signature == null");
		}
		if (otsHashAddress == null) {
			throw new NullPointerException("otsHashAddress == null");
		}

		/* prepare adresses */
		LTreeAddress lTreeAddress = (LTreeAddress) new LTreeAddress.Builder()
				.withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
				.withLTreeAddress(otsHashAddress.getOTSAddress()).build();
		HashTreeAddress hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder()
				.withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
				.withTreeIndex(otsHashAddress.getOTSAddress()).build();
		/*
		 * calculate WOTS+ public key and compress to obtain original leaf hash
		 */
		WOTSPlusPublicKeyParameters wotsPlusPK = wotsPlus.getPublicKeyFromSignature(messageDigest,
				signature.getWOTSPlusSignature(), otsHashAddress);
		XMSSNode[] node = new XMSSNode[2];
		node[0] = lTree(wotsPlusPK, lTreeAddress);

		for (int k = 0; k < params.getHeight(); k++) {
			hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder()
					.withLayerAddress(hashTreeAddress.getLayerAddress())
					.withTreeAddress(hashTreeAddress.getTreeAddress()).withTreeHeight(k)
					.withTreeIndex(hashTreeAddress.getTreeIndex()).withKeyAndMask(hashTreeAddress.getKeyAndMask())
					.build();
			if (Math.floor(privateKey.getIndex() / (1 << k)) % 2 == 0) {
				hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder()
						.withLayerAddress(hashTreeAddress.getLayerAddress())
						.withTreeAddress(hashTreeAddress.getTreeAddress())
						.withTreeHeight(hashTreeAddress.getTreeHeight())
						.withTreeIndex(hashTreeAddress.getTreeIndex() / 2)
						.withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
				node[1] = randomizeHash(node[0], signature.getAuthPath().get(k), hashTreeAddress);
				node[1] = new XMSSNode(node[1].getHeight() + 1, node[1].getValue());
			} else {
				hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder()
						.withLayerAddress(hashTreeAddress.getLayerAddress())
						.withTreeAddress(hashTreeAddress.getTreeAddress())
						.withTreeHeight(hashTreeAddress.getTreeHeight())
						.withTreeIndex((hashTreeAddress.getTreeIndex() - 1) / 2)
						.withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
				node[1] = randomizeHash(signature.getAuthPath().get(k), node[0], hashTreeAddress);
				node[1] = new XMSSNode(node[1].getHeight() + 1, node[1].getValue());
			}
			node[0] = node[1];
		}
		return node[0];
	}

	/**
	 * Derive WOTS+ secret key for specific index as in XMSS ref impl Andreas
	 * Huelsing.
	 *
	 * @param otsHashAddress
	 * @return WOTS+ secret key at index.
	 */
	protected byte[] getWOTSPlusSecretKey(OTSHashAddress otsHashAddress) {
		otsHashAddress = (OTSHashAddress) new OTSHashAddress.Builder()
				.withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
				.withOTSAddress(otsHashAddress.getOTSAddress()).build();
		return khf.PRF(privateKey.getSecretKeySeed(), otsHashAddress.toByteArray());
	}

	/**
	 * Getter XMSS params.
	 *
	 * @return XMSS params.
	 */
	public XMSSParameters getParams() {
		return params;
	}

	/**
	 * Getter WOTS+.
	 *
	 * @return WOTS+ instance.
	 */
	protected WOTSPlus getWOTSPlus() {
		return wotsPlus;
	}

	protected KeyedHashFunctions getKhf() {
		return khf;
	}

	/**
	 * Getter XMSS root.
	 *
	 * @return Root of binary tree.
	 */
	public byte[] getRoot() {
		return privateKey.getRoot();
	}

	protected void setRoot(byte[] root) {
		try {
			privateKey = new XMSSPrivateKeyParameters.Builder(params).withIndex(privateKey.getIndex())
					.withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF())
					.withPublicSeed(getPublicSeed()).withRoot(root).withBDSState(privateKey.getBDSState()).build();
			publicKey = new XMSSPublicKeyParameters.Builder(params).withRoot(root).withPublicSeed(getPublicSeed())
					.build();
		} catch (ParseException ex) {
			/* should not be possible */
			ex.printStackTrace();
		} catch (ClassNotFoundException e) {
			/* should not be possible */
			e.printStackTrace();
		} catch (IOException e) {
			/* should not be possible */
			e.printStackTrace();
		}
	}

	/**
	 * Getter XMSS index.
	 *
	 * @return Index.
	 */
	public int getIndex() {
		return privateKey.getIndex();
	}

	protected void setIndex(int index) {
		try {
			privateKey = new XMSSPrivateKeyParameters.Builder(params).withIndex(index)
					.withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF())
					.withPublicSeed(privateKey.getPublicSeed()).withRoot(privateKey.getRoot())
					.withBDSState(privateKey.getBDSState()).build();
		} catch (ParseException ex) {
			/* should not happen */
			ex.printStackTrace();
		} catch (ClassNotFoundException e) {
			/* should not be possible */
			e.printStackTrace();
		} catch (IOException e) {
			/* should not be possible */
			e.printStackTrace();
		}
	}

	/**
	 * Getter XMSS public seed.
	 *
	 * @return Public seed.
	 */
	public byte[] getPublicSeed() {
		return privateKey.getPublicSeed();
	}

	protected void setPublicSeed(byte[] publicSeed) {
		try {
			privateKey = new XMSSPrivateKeyParameters.Builder(params).withIndex(privateKey.getIndex())
					.withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF())
					.withPublicSeed(publicSeed).withRoot(getRoot()).withBDSState(privateKey.getBDSState()).build();
			publicKey = new XMSSPublicKeyParameters.Builder(params).withRoot(getRoot()).withPublicSeed(publicSeed)
					.build();
		} catch (ParseException ex) {
			/* should not happen */
			ex.printStackTrace();
		} catch (ClassNotFoundException e) {
			/* should not be possible */
			e.printStackTrace();
		} catch (IOException e) {
			/* should not be possible */
			e.printStackTrace();
		}
		wotsPlus.importKeys(new byte[params.getDigestSize()], publicSeed);
	}

	protected BDS getBDSState() {
		return privateKey.getBDSState();
	}
}
