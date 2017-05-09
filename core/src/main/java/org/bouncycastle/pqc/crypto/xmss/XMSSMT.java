package org.bouncycastle.pqc.crypto.xmss;

import java.io.IOException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Map;
import java.util.TreeMap;

/**
 * XMSS^MT.
 *
 */
public final class XMSSMT {

	private XMSSMTParameters params;
	private XMSS xmss;
	private SecureRandom prng;
	private KeyedHashFunctions khf;
	private XMSSMTPrivateKeyParameters privateKey;
	private XMSSMTPublicKeyParameters publicKey;

	/**
	 * XMSSMT constructor...
	 *
	 * @param params
	 *            XMSSMTParameters.
	 */
	public XMSSMT(XMSSMTParameters params) {
		super();
		if (params == null) {
			throw new NullPointerException("params == null");
		}
		this.params = params;
		xmss = params.getXMSS();
		prng = params.getXMSS().getParams().getPRNG();
		khf = xmss.getKhf();
		try {
			privateKey = new XMSSMTPrivateKeyParameters.Builder(params).build();
			publicKey = new XMSSMTPublicKeyParameters.Builder(params).build();
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
	 * Generate a new XMSSMT private key / public key pair.
	 * 
	 */
	public void generateKeys() {
		/* generate XMSSMT private key */
		privateKey = generatePrivateKey();

		/* init global xmss */
		XMSSPrivateKeyParameters xmssPrivateKey = null;
		XMSSPublicKeyParameters xmssPublicKey = null;
		try {
			xmssPrivateKey = new XMSSPrivateKeyParameters.Builder(xmss.getParams())
					.withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF())
					.withPublicSeed(privateKey.getPublicSeed()).withBDSState(new BDS(xmss)).build();
			xmssPublicKey = new XMSSPublicKeyParameters.Builder(xmss.getParams()).withPublicSeed(getPublicSeed())
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

		/* import to xmss */
		try {
			xmss.importState(xmssPrivateKey.toByteArray(), xmssPublicKey.toByteArray());
		} catch (ParseException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		/* get root */
		int rootLayerIndex = params.getLayers() - 1;
		OTSHashAddress otsHashAddress = (OTSHashAddress) new OTSHashAddress.Builder().withLayerAddress(rootLayerIndex)
				.build();

		/* store BDS instance of root xmss instance */
		BDS bdsRoot = new BDS(xmss);
		XMSSNode root = bdsRoot.initialize(otsHashAddress);
		getBDSState().put(rootLayerIndex, bdsRoot);
		xmss.setRoot(root.getValue());

		/* set XMSS^MT root / create public key */
		try {
			privateKey = new XMSSMTPrivateKeyParameters.Builder(params).withSecretKeySeed(privateKey.getSecretKeySeed())
					.withSecretKeyPRF(privateKey.getSecretKeyPRF()).withPublicSeed(privateKey.getPublicSeed())
					.withRoot(xmss.getRoot()).withBDSState(privateKey.getBDSState()).build();
			publicKey = new XMSSMTPublicKeyParameters.Builder(params).withRoot(root.getValue())
					.withPublicSeed(getPublicSeed()).build();
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

	private XMSSMTPrivateKeyParameters generatePrivateKey() {
		int n = params.getDigestSize();
		byte[] secretKeySeed = new byte[n];
		prng.nextBytes(secretKeySeed);
		byte[] secretKeyPRF = new byte[n];
		prng.nextBytes(secretKeyPRF);
		byte[] publicSeed = new byte[n];
		prng.nextBytes(publicSeed);

		XMSSMTPrivateKeyParameters privateKey = null;
		try {
			privateKey = new XMSSMTPrivateKeyParameters.Builder(params).withSecretKeySeed(secretKeySeed)
					.withSecretKeyPRF(secretKeyPRF).withPublicSeed(publicSeed)
					.withBDSState(this.privateKey.getBDSState()).build();
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
		return privateKey;
	}

	/**
	 * Import XMSSMT private key / public key pair.
	 * 
	 * @param privateKey
	 *            XMSSMT private key.
	 * @param publicKey
	 *            XMSSMT public key.
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
		XMSSMTPrivateKeyParameters xmssMTPrivateKey = new XMSSMTPrivateKeyParameters.Builder(params)
				.withPrivateKey(privateKey, xmss).build();
		XMSSMTPublicKeyParameters xmssMTPublicKey = new XMSSMTPublicKeyParameters.Builder(params)
				.withPublicKey(publicKey).build();
		if (!XMSSUtil.compareByteArray(xmssMTPrivateKey.getRoot(), xmssMTPublicKey.getRoot())) {
			throw new IllegalStateException("root of private key and public key do not match");
		}
		if (!XMSSUtil.compareByteArray(xmssMTPrivateKey.getPublicSeed(), xmssMTPublicKey.getPublicSeed())) {
			throw new IllegalStateException("public seed of private key and public key do not match");
		}

		/* init global xmss */
		XMSSPrivateKeyParameters xmssPrivateKey = new XMSSPrivateKeyParameters.Builder(xmss.getParams())
				.withSecretKeySeed(xmssMTPrivateKey.getSecretKeySeed())
				.withSecretKeyPRF(xmssMTPrivateKey.getSecretKeyPRF()).withPublicSeed(xmssMTPrivateKey.getPublicSeed())
				.withRoot(xmssMTPrivateKey.getRoot()).withBDSState(new BDS(xmss)).build();
		XMSSPublicKeyParameters xmssPublicKey = new XMSSPublicKeyParameters.Builder(xmss.getParams())
				.withRoot(xmssMTPrivateKey.getRoot()).withPublicSeed(getPublicSeed()).build();

		/* import to xmss */
		xmss.importState(xmssPrivateKey.toByteArray(), xmssPublicKey.toByteArray());
		this.privateKey = xmssMTPrivateKey;
		this.publicKey = xmssMTPublicKey;
	}

	/**
	 * Sign message.
	 *
	 * @param message
	 *            Message to sign.
	 * @return XMSSMT signature on digest of message.
	 */
	public byte[] sign(byte[] message) {
		if (message == null) {
			throw new NullPointerException("message == null");
		}
		if (getBDSState().isEmpty()) {
			throw new IllegalStateException("not initialized");
		}
		// privateKey.increaseIndex(this);
		long globalIndex = getIndex();
		int totalHeight = params.getHeight();
		int xmssHeight = xmss.getParams().getHeight();
		if (!XMSSUtil.isIndexValid(totalHeight, globalIndex)) {
			throw new IllegalArgumentException("index out of bounds");
		}

		/* compress message */
		byte[] random = khf.PRF(privateKey.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian(globalIndex, 32));
		byte[] concatenated = XMSSUtil.concat(random, privateKey.getRoot(),
				XMSSUtil.toBytesBigEndian(globalIndex, params.getDigestSize()));
		byte[] messageDigest = khf.HMsg(concatenated, message);

		XMSSMTSignature signature = null;
		try {
			signature = new XMSSMTSignature.Builder(params).withIndex(globalIndex).withRandom(random).build();
		} catch (ParseException ex) {
			/* should not be possible */
			ex.printStackTrace();
		}

		/* layer 0 */
		long indexTree = XMSSUtil.getTreeIndex(globalIndex, xmssHeight);
		int indexLeaf = XMSSUtil.getLeafIndex(globalIndex, xmssHeight);

		/* reset xmss */
		xmss.setIndex(indexLeaf);
		xmss.setPublicSeed(getPublicSeed());

		/* create signature with XMSS tree on layer 0 */

		/* adjust addresses */
		OTSHashAddress otsHashAddress = (OTSHashAddress) new OTSHashAddress.Builder().withTreeAddress(indexTree)
				.withOTSAddress(indexLeaf).build();

		/* sign message digest */
		WOTSPlusSignature wotsPlusSignature = xmss.wotsSign(messageDigest, otsHashAddress);
		/* get authentication path from BDS */
		if (getBDSState().get(0) == null || indexLeaf == 0) {
			getBDSState().put(0, new BDS(xmss));
			getBDSState().get(0).initialize(otsHashAddress);
		}

		XMSSReducedSignature reducedSignature = null;
		try {
			reducedSignature = new XMSSReducedSignature.Builder(xmss.getParams())
					.withWOTSPlusSignature(wotsPlusSignature).withAuthPath(getBDSState().get(0).getAuthenticationPath())
					.build();
		} catch (ParseException ex) {
			/* should never happen */
			ex.printStackTrace();
		}
		signature.getReducedSignatures().add(reducedSignature);

		/* prepare authentication path for next leaf */
		if (indexLeaf < ((1 << xmssHeight) - 1)) {
			getBDSState().get(0).nextAuthenticationPath(otsHashAddress);
		}

		/* loop over remaining layers */
		for (int layer = 1; layer < params.getLayers(); layer++) {
			/* get root of layer - 1 */
			XMSSNode root = getBDSState().get(layer - 1).getRoot();

			indexLeaf = XMSSUtil.getLeafIndex(indexTree, xmssHeight);
			indexTree = XMSSUtil.getTreeIndex(indexTree, xmssHeight);
			xmss.setIndex(indexLeaf);

			/* adjust addresses */
			otsHashAddress = (OTSHashAddress) new OTSHashAddress.Builder().withLayerAddress(layer)
					.withTreeAddress(indexTree).withOTSAddress(indexLeaf).build();

			/* sign root digest of layer - 1 */
			wotsPlusSignature = xmss.wotsSign(root.getValue(), otsHashAddress);
			/* get authentication path from BDS */
			if (getBDSState().get(layer) == null || XMSSUtil.isNewBDSInitNeeded(globalIndex, xmssHeight, layer)) {
				getBDSState().put(layer, new BDS(xmss));
				getBDSState().get(layer).initialize(otsHashAddress);
			}
			try {
				reducedSignature = new XMSSReducedSignature.Builder(xmss.getParams())
						.withWOTSPlusSignature(wotsPlusSignature)
						.withAuthPath(getBDSState().get(layer).getAuthenticationPath()).build();
			} catch (ParseException ex) {
				/* should never happen */
				ex.printStackTrace();
			}
			signature.getReducedSignatures().add(reducedSignature);

			/* prepare authentication path for next leaf */
			if (indexLeaf < ((1 << xmssHeight) - 1)
					&& XMSSUtil.isNewAuthenticationPathNeeded(globalIndex, xmssHeight, layer)) {
				getBDSState().get(layer).nextAuthenticationPath(otsHashAddress);
			}
		}

		/* update private key */
		try {
			privateKey = new XMSSMTPrivateKeyParameters.Builder(params).withIndex(globalIndex + 1)
					.withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF())
					.withPublicSeed(privateKey.getPublicSeed()).withRoot(privateKey.getRoot())
					.withBDSState(privateKey.getBDSState()).build();
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
		return signature.toByteArray();
	}

	/**
	 * Verify an XMSSMT signature.
	 * 
	 * @param message
	 *            Message.
	 * @param signature
	 *            XMSSMT signature.
	 * @param publicKey
	 *            XMSSMT public key.
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
		/* (re)create compressed message */
		XMSSMTSignature sig = new XMSSMTSignature.Builder(params).withSignature(signature).build();
		XMSSMTPublicKeyParameters pubKey = new XMSSMTPublicKeyParameters.Builder(params).withPublicKey(publicKey)
				.build();

		byte[] concatenated = XMSSUtil.concat(sig.getRandom(), pubKey.getRoot(),
				XMSSUtil.toBytesBigEndian(sig.getIndex(), params.getDigestSize()));
		byte[] messageDigest = khf.HMsg(concatenated, message);

		long globalIndex = sig.getIndex();
		int xmssHeight = xmss.getParams().getHeight();
		long indexTree = XMSSUtil.getTreeIndex(globalIndex, xmssHeight);
		int indexLeaf = XMSSUtil.getLeafIndex(globalIndex, xmssHeight);

		/* adjust xmss */
		xmss.setIndex(indexLeaf);
		xmss.setPublicSeed(pubKey.getPublicSeed());

		/* prepare addresses */
		OTSHashAddress otsHashAddress = (OTSHashAddress) new OTSHashAddress.Builder().withTreeAddress(indexTree)
				.withOTSAddress(indexLeaf).build();

		/* get root node on layer 0 */
		XMSSReducedSignature xmssMTSignature = sig.getReducedSignatures().get(0);
		XMSSNode rootNode = xmss.getRootNodeFromSignature(messageDigest, xmssMTSignature, otsHashAddress);
		for (int layer = 1; layer < params.getLayers(); layer++) {
			xmssMTSignature = sig.getReducedSignatures().get(layer);
			indexLeaf = XMSSUtil.getLeafIndex(indexTree, xmssHeight);
			indexTree = XMSSUtil.getTreeIndex(indexTree, xmssHeight);
			xmss.setIndex(indexLeaf);

			/* adjust address */
			otsHashAddress = (OTSHashAddress) new OTSHashAddress.Builder().withLayerAddress(layer)
					.withTreeAddress(indexTree).withOTSAddress(indexLeaf).build();

			/* get root node */
			rootNode = xmss.getRootNodeFromSignature(rootNode.getValue(), xmssMTSignature, otsHashAddress);
		}

		/* compare roots */
		return XMSSUtil.compareByteArray(rootNode.getValue(), pubKey.getRoot());
	}

	/**
	 * Export XMSSMT private key.
	 *
	 * @return XMSSMT private key.
	 */
	public byte[] exportPrivateKey() {
		return privateKey.toByteArray();
	}

	/**
	 * Export XMSSMT public key.
	 *
	 * @return XMSSMT public key.
	 */
	public byte[] exportPublicKey() {
		return publicKey.toByteArray();
	}

	/**
	 * Getter XMSSMT params.
	 *
	 * @return XMSSMT params.
	 */
	public XMSSMTParameters getParams() {
		return params;
	}

	/**
	 * Getter XMSSMT index.
	 *
	 * @return XMSSMT index.
	 */
	public long getIndex() {
		return privateKey.getIndex();
	}

	/**
	 * Getter public seed.
	 *
	 * @return Public seed.
	 */
	public byte[] getPublicSeed() {
		return privateKey.getPublicSeed();
	}

	protected Map<Integer, BDS> getBDSState() {
		return privateKey.getBDSState();
	}

	protected XMSS getXMSS() {
		return xmss;
	}
}
