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
	private Map<Integer, BDS> bdsState;
	private SecureRandom prng;
	private KeyedHashFunctions khf;
	private XMSSMTPrivateKeyParameters privateKey;
	private XMSSMTPublicKeyParameters publicKey;

	public XMSSMT(XMSSMTParameters params) {
		super();
		if (params == null) {
			throw new NullPointerException("params == null");
		}
		this.params = params;
		xmss = params.getXMSS();
		bdsState = new TreeMap<Integer, BDS>();
		prng = params.getXMSS().getParams().getPRNG();
		khf = xmss.getKhf();
		try {
			privateKey = new XMSSMTPrivateKeyParameters.Builder(params).build();
			publicKey = new XMSSMTPublicKeyParameters.Builder(params).build();
		} catch (ParseException ex) {
			/* should not be possible */
			ex.printStackTrace();
		}
	}

	public void generateKeys() {
		/* generate private key */
		privateKey = generatePrivateKey();

		/* init global xmss */
		XMSSPrivateKeyParameters xmssPrivateKey = null;
		XMSSPublicKeyParameters xmssPublicKey = null;
		try {
			xmssPrivateKey = new XMSSPrivateKeyParameters.Builder(xmss.getParams())
					.withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF())
					.withPublicSeed(privateKey.getPublicSeed()).build();
			xmssPublicKey = new XMSSPublicKeyParameters.Builder(xmss.getParams()).withPublicSeed(getPublicSeed())
					.build();
		} catch (ParseException ex) {
			/* should not happen */
			ex.printStackTrace();
		}

		/* import to xmss */
		try {
			xmss.importKeys(xmssPrivateKey.toByteArray(), xmssPublicKey.toByteArray());
		} catch (ParseException e) {
			e.printStackTrace();
		}

		/* get root */
		int rootLayerIndex = params.getLayers() - 1;
		OTSHashAddress otsHashAddress = (OTSHashAddress) new OTSHashAddress.Builder().withLayerAddress(rootLayerIndex)
				.build();

		/* store BDS instance of root xmss instance */
		BDS bdsRoot = new BDS(xmss);
		XMSSNode root = bdsRoot.initialize(otsHashAddress);
		bdsState.put(rootLayerIndex, bdsRoot);
		xmss.setRoot(root.getValue());

		/* set XMSS^MT root / create public key */
		try {
			privateKey = new XMSSMTPrivateKeyParameters.Builder(params).withSecretKeySeed(privateKey.getSecretKeySeed())
					.withSecretKeyPRF(privateKey.getSecretKeyPRF()).withPublicSeed(privateKey.getPublicSeed())
					.withRoot(xmss.getRoot()).build();
			publicKey = new XMSSMTPublicKeyParameters.Builder(params).withRoot(root.getValue())
					.withPublicSeed(getPublicSeed()).build();
		} catch (ParseException ex) {
			/* should not happen */
			ex.printStackTrace();
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
					.withSecretKeyPRF(secretKeyPRF).withPublicSeed(publicSeed).build();
		} catch (ParseException ex) {
			/* should not be possible */
			ex.printStackTrace();
		}
		return privateKey;
	}

	public void importState(byte[] privateKey, byte[] publicKey, byte[] bdsState)
			throws ParseException, ClassNotFoundException, IOException {
		if (privateKey == null) {
			throw new NullPointerException("privateKey == null");
		}
		if (publicKey == null) {
			throw new NullPointerException("publicKey == null");
		}
		if (bdsState == null) {
			throw new NullPointerException("bdsState == null");
		}
		XMSSMTPrivateKeyParameters xmssMTPrivateKey = new XMSSMTPrivateKeyParameters.Builder(params)
				.withPrivateKey(privateKey).build();
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
				.withRoot(xmssMTPrivateKey.getRoot()).build();
		XMSSPublicKeyParameters xmssPublicKey = new XMSSPublicKeyParameters.Builder(xmss.getParams())
				.withRoot(xmssMTPrivateKey.getRoot()).withPublicSeed(getPublicSeed()).build();

		/* import to xmss */
		xmss.importKeys(xmssPrivateKey.toByteArray(), xmssPublicKey.toByteArray());
		this.privateKey = xmssMTPrivateKey;
		this.publicKey = xmssMTPublicKey;

		/* import BDS state */
		@SuppressWarnings("unchecked")
		Map<Integer, BDS> bdsStatesImport = (TreeMap<Integer, BDS>) XMSSUtil.deserialize(bdsState);
		for (Integer key : bdsStatesImport.keySet()) {
			BDS bds = bdsStatesImport.get(key);
			bds.setXMSS(xmss);
			if (key == (params.getLayers() - 1)) {
				bds.validate(true);
			} else {
				bds.validate(false);
			}
		}
		this.bdsState = bdsStatesImport;
	}

	public byte[] sign(byte[] message) {
		if (message == null) {
			throw new NullPointerException("message == null");
		}
		if (bdsState.isEmpty()) {
			throw new IllegalStateException("not initialized");
		}
		//privateKey.increaseIndex(this);
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
		if (bdsState.get(0) == null || indexLeaf == 0) {
			bdsState.put(0, new BDS(xmss));
			bdsState.get(0).initialize(otsHashAddress);
		}

		XMSSReducedSignature reducedSignature = null;
		try {
			reducedSignature = new XMSSReducedSignature.Builder(xmss.getParams())
					.withWOTSPlusSignature(wotsPlusSignature).withAuthPath(bdsState.get(0).getAuthenticationPath())
					.build();
		} catch (ParseException ex) {
			/* should never happen */
			ex.printStackTrace();
		}
		signature.getReducedSignatures().add(reducedSignature);

		/* prepare authentication path for next leaf */
		if (indexLeaf < ((1 << xmssHeight) - 1)) {
			bdsState.get(0).nextAuthenticationPath(otsHashAddress);
		}

		/* loop over remaining layers */
		for (int layer = 1; layer < params.getLayers(); layer++) {
			/* get root of layer - 1 */
			XMSSNode root = bdsState.get(layer - 1).getRoot();

			indexLeaf = XMSSUtil.getLeafIndex(indexTree, xmssHeight);
			indexTree = XMSSUtil.getTreeIndex(indexTree, xmssHeight);
			xmss.setIndex(indexLeaf);

			/* adjust addresses */
			otsHashAddress = (OTSHashAddress) new OTSHashAddress.Builder().withLayerAddress(layer)
					.withTreeAddress(indexTree).withOTSAddress(indexLeaf).build();

			/* sign root digest of layer - 1 */
			wotsPlusSignature = xmss.wotsSign(root.getValue(), otsHashAddress);
			/* get authentication path from BDS */
			if (bdsState.get(layer) == null || XMSSUtil.isNewBDSInitNeeded(globalIndex, xmssHeight, layer)) {
				bdsState.put(layer, new BDS(xmss));
				bdsState.get(layer).initialize(otsHashAddress);
			}
			try {
				reducedSignature = new XMSSReducedSignature.Builder(xmss.getParams())
						.withWOTSPlusSignature(wotsPlusSignature)
						.withAuthPath(bdsState.get(layer).getAuthenticationPath()).build();
			} catch (ParseException ex) {
				/* should never happen */
				ex.printStackTrace();
			}
			signature.getReducedSignatures().add(reducedSignature);

			/* prepare authentication path for next leaf */
			if (indexLeaf < ((1 << xmssHeight) - 1)
					&& XMSSUtil.isNewAuthenticationPathNeeded(globalIndex, xmssHeight, layer)) {
				bdsState.get(layer).nextAuthenticationPath(otsHashAddress);
			}
		}

		/* update private key */
		try {
			privateKey = new XMSSMTPrivateKeyParameters.Builder(params).withIndex(globalIndex + 1)
					.withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF())
					.withPublicSeed(privateKey.getPublicSeed()).withRoot(privateKey.getRoot()).build();
		} catch (ParseException ex) {
			/* should not be possible */
			ex.printStackTrace();
		}
		return signature.toByteArray();
	}

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
	 * Export XMSS^MT private key.
	 *
	 * @return XMSS^MT private key.
	 */
	public byte[] exportPrivateKey() {
		return privateKey.toByteArray();
	}

	/**
	 * Export XMSS^MT public key.
	 *
	 * @return XMSS^MT public key.
	 */
	public byte[] exportPublicKey() {
		return publicKey.toByteArray();
	}

	/**
	 * Export XMSS^MT BDS state.
	 *
	 * @return XMSS^MT BDS state.
	 * @throws IOException
	 */
	public byte[] exportBDSState() throws IOException {
		return XMSSUtil.serialize(bdsState);
	}

	public XMSSMTParameters getParams() {
		return params;
	}

	public long getIndex() {
		return privateKey.getIndex();
	}

	public byte[] getPublicSeed() {
		return privateKey.getPublicSeed();
	}

	protected Map<Integer, BDS> getBDS() {
		return bdsState;
	}

	protected XMSS getXMSS() {
		return xmss;
	}
}
