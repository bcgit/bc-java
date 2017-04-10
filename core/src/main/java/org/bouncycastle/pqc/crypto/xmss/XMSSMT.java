package org.bouncycastle.pqc.crypto.xmss;

import java.io.IOException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Map;
import java.util.TreeMap;

/**
 * XMSS^MT.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSMT {

	private XMSSMTParameters params;
	private XMSS xmss;
	private Map<Integer, BDS> bdsState;
	private SecureRandom prng;
	private KeyedHashFunctions khf;
	private XMSSMTPrivateKey privateKey;
	private XMSSMTPublicKey publicKey;
	

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
		privateKey = new XMSSMTPrivateKey(params);
		publicKey = new XMSSMTPublicKey(params);
	}
	
	public void generateKeys() {
		/* generate private key */
		privateKey = generatePrivateKey();
		
		/* init global xmss */
		XMSSPrivateKey xmssPrivateKey = new XMSSPrivateKey(xmss.getParams());
		xmssPrivateKey.setSecretKeySeed(privateKey.getSecretKeySeed());
		xmssPrivateKey.setSecretKeyPRF(privateKey.getSecretKeyPRF());
		xmssPrivateKey.setPublicSeed(privateKey.getPublicSeed());
		xmssPrivateKey.setRoot(new byte[params.getDigestSize()]);

		XMSSPublicKey xmssPublicKey = new XMSSPublicKey(xmss.getParams());
		xmssPublicKey.setPublicSeed(privateKey.getPublicSeed());
		xmssPublicKey.setRoot(new byte[params.getDigestSize()]);
		
		/* import to xmss */
		try {
			xmss.importKeys(xmssPrivateKey.toByteArray(), xmssPublicKey.toByteArray());
		} catch (ParseException e) {
			e.printStackTrace();
		}

		/* get root */
		int rootLayerIndex = params.getLayers() - 1;
		OTSHashAddress otsHashAddress = new OTSHashAddress();
		otsHashAddress.setLayerAddress(rootLayerIndex);
		otsHashAddress.setTreeAddress(0);
		
		/* store BDS instance of root xmss instance */
		BDS bdsRoot = new BDS(xmss);
		XMSSNode root = bdsRoot.initialize(otsHashAddress);
		bdsState.put(rootLayerIndex, bdsRoot);
		xmss.setRoot(root.getValue());
		
		/* set XMSS^MT root */
		privateKey.setRoot(xmss.getRoot());
		
		/* create XMSS^MT public key */
		publicKey = new XMSSMTPublicKey(params);
		publicKey.setPublicSeed(xmss.getPublicSeed());
		publicKey.setRoot(xmss.getRoot());
	}
	
	private XMSSMTPrivateKey generatePrivateKey() {
		int n = params.getDigestSize();
		byte[] publicSeed = new byte[n];
		prng.nextBytes(publicSeed);
		byte[] secretKeySeed = new byte[n];
		prng.nextBytes(secretKeySeed);
		byte[] secretKeyPRF = new byte[n];
		prng.nextBytes(secretKeyPRF);
		
		XMSSMTPrivateKey privateKey = new XMSSMTPrivateKey(params);
		privateKey.setPublicSeed(publicSeed);
		privateKey.setSecretKeySeed(secretKeySeed);
		privateKey.setSecretKeyPRF(secretKeyPRF);
		return privateKey;
	}
	
	public void importState(byte[] privateKey, byte[] publicKey, byte[] bdsState) throws ParseException, ClassNotFoundException, IOException {
		if (privateKey == null) {
			throw new NullPointerException("privateKey == null");
		}
		if (publicKey == null) {
			throw new NullPointerException("publicKey == null");
		}
		if (bdsState == null) {
			throw new NullPointerException("bdsState == null");
		}
		XMSSMTPrivateKey xmssMTPrivateKey = new XMSSMTPrivateKey(params);
		xmssMTPrivateKey.parseByteArray(privateKey);
		XMSSMTPublicKey xmssMTPublicKey = new XMSSMTPublicKey(params);
		xmssMTPublicKey.parseByteArray(publicKey);
		if (!XMSSUtil.compareByteArray(xmssMTPrivateKey.getRoot(), xmssMTPublicKey.getRoot())) {
			throw new IllegalStateException("root of private key and public key do not match");
		}
		if (!XMSSUtil.compareByteArray(xmssMTPrivateKey.getPublicSeed(), xmssMTPublicKey.getPublicSeed())) {
			throw new IllegalStateException("public seed of private key and public key do not match");
		}

		/* init global xmss */
		XMSSPrivateKey xmssPrivateKey = new XMSSPrivateKey(xmss.getParams());
		xmssPrivateKey.setSecretKeySeed(xmssMTPrivateKey.getSecretKeySeed());
		xmssPrivateKey.setSecretKeyPRF(xmssMTPrivateKey.getSecretKeyPRF());
		xmssPrivateKey.setPublicSeed(xmssMTPrivateKey.getPublicSeed());
		xmssPrivateKey.setRoot(xmssMTPrivateKey.getRoot());

		XMSSPublicKey xmssPublicKey = new XMSSPublicKey(xmss.getParams());
		xmssPublicKey.setPublicSeed(xmssMTPrivateKey.getPublicSeed());
		xmssPublicKey.setRoot(xmssMTPrivateKey.getRoot());
		
		/* import to xmss */
		xmss.importKeys(xmssPrivateKey.toByteArray(), xmssPublicKey.toByteArray());
		this.privateKey = xmssMTPrivateKey;
		this.publicKey = xmssMTPublicKey;
		
		/* import BDS state */
		@SuppressWarnings("unchecked")
		Map<Integer, BDS> bdsStatesImport = (TreeMap<Integer, BDS>)XMSSUtil.deserialize(bdsState);
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
		long globalIndex = getIndex();
		int totalHeight = params.getHeight();
		int xmssHeight = xmss.getParams().getHeight();
		if (!XMSSUtil.isIndexValid(totalHeight, globalIndex)) {
			throw new IllegalArgumentException("index out of bounds");
		}
		XMSSMTSignature signature = new XMSSMTSignature(params);
		signature.setIndex(globalIndex);

		/* compress message */
		byte[] random =  khf.PRF(privateKey.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian(globalIndex, 32));
		signature.setRandom(random);
		byte[] concatenated = XMSSUtil.concat(random, privateKey.getRoot(), XMSSUtil.toBytesBigEndian(globalIndex, params.getDigestSize()));
		byte[] messageDigest = khf.HMsg(concatenated, message);
		
		/* layer 0 */
		long indexTree = XMSSUtil.getTreeIndex(globalIndex, xmssHeight);
		int indexLeaf = XMSSUtil.getLeafIndex(globalIndex, xmssHeight);
		
		/* reset xmss */
		xmss.setIndex(indexLeaf);
		xmss.setPublicSeed(getPublicSeed());
		
		/* create signature with XMSS tree on layer 0 */

		/* adjust addresses */
		OTSHashAddress otsHashAddress = new OTSHashAddress();
		otsHashAddress.setLayerAddress(0);
		otsHashAddress.setTreeAddress(indexTree);
		otsHashAddress.setOTSAddress(indexLeaf);
		
		/* sign message digest */
		XMSSSignature tmpSignature = xmss.treeSig(messageDigest, otsHashAddress);
		/* get authentication path from BDS */
		if (bdsState.get(0) == null || indexLeaf == 0) {
			bdsState.put(0, new BDS(xmss));
			bdsState.get(0).initialize(otsHashAddress);
		}
		
		XMSSReducedSignature reducedSignature = new XMSSReducedSignature(xmss.getParams());
		reducedSignature.setSignature(tmpSignature.getSignature());
		reducedSignature.setAuthPath(bdsState.get(0).getAuthenticationPath());
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
			
			/* reinitialize WOTS+ object */
			otsHashAddress.setLayerAddress(layer);
			otsHashAddress.setTreeAddress(indexTree);
			otsHashAddress.setOTSAddress(indexLeaf);
			
			/* sign root digest of layer - 1 */
			tmpSignature = xmss.treeSig(root.getValue(), otsHashAddress);
			/* get authentication path from BDS */
			if (bdsState.get(layer) == null || XMSSUtil.isNewBDSInitNeeded(globalIndex, xmssHeight, layer)) {
				bdsState.put(layer, new BDS(xmss));
				bdsState.get(layer).initialize(otsHashAddress);
			}
			reducedSignature = new XMSSReducedSignature(xmss.getParams());
			reducedSignature.setSignature(tmpSignature.getSignature());
			reducedSignature.setAuthPath(bdsState.get(layer).getAuthenticationPath());
			signature.getReducedSignatures().add(reducedSignature);
			
			/* prepare authentication path for next leaf */
			if (indexLeaf < ((1 << xmssHeight) - 1) && XMSSUtil.isNewAuthenticationPathNeeded(globalIndex, xmssHeight, layer)) {
				bdsState.get(layer).nextAuthenticationPath(otsHashAddress);
			}
		}
		
		/* update private key */
		privateKey.setIndex(globalIndex + 1);
		
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
		XMSSMTSignature sig = new XMSSMTSignature(params);
		sig.parseByteArray(signature);
		XMSSMTPublicKey pubKey = new XMSSMTPublicKey(params);
		pubKey.parseByteArray(publicKey);
		
		byte[] concatenated = XMSSUtil.concat(sig.getRandom(), pubKey.getRoot(), XMSSUtil.toBytesBigEndian(sig.getIndex(), params.getDigestSize()));
		byte[] messageDigest = khf.HMsg(concatenated, message);

		long globalIndex = sig.getIndex();
		int xmssHeight = xmss.getParams().getHeight();
		long indexTree = XMSSUtil.getTreeIndex(globalIndex, xmssHeight);
		int indexLeaf = XMSSUtil.getLeafIndex(globalIndex, xmssHeight);
		
		/* adjust xmss */
		xmss.setIndex(indexLeaf);
		xmss.setPublicSeed(pubKey.getPublicSeed());
		
		/* prepare addresses */
		OTSHashAddress otsHashAddress = new OTSHashAddress();
		otsHashAddress.setLayerAddress(0);
		otsHashAddress.setTreeAddress(indexTree);
		otsHashAddress.setOTSAddress(indexLeaf);
		
		/* get root node on layer 0 */
		XMSSReducedSignature xmssMTSignature = sig.getReducedSignatures().get(0);
		XMSSNode rootNode = xmss.getRootNodeFromSignature(messageDigest, xmssMTSignature, otsHashAddress);
		for (int layer = 1; layer < params.getLayers(); layer++) {
			xmssMTSignature = sig.getReducedSignatures().get(layer);
			indexLeaf = XMSSUtil.getLeafIndex(indexTree, xmssHeight);
			indexTree = XMSSUtil.getTreeIndex(indexTree, xmssHeight);
			xmss.setIndex(indexLeaf);
			
			/* adjust address */
			otsHashAddress.setLayerAddress(layer);
			otsHashAddress.setTreeAddress(indexTree);
			otsHashAddress.setOTSAddress(indexLeaf);
			
			/* get root node */
			rootNode = xmss.getRootNodeFromSignature(rootNode.getValue(), xmssMTSignature, otsHashAddress);
		}
		
		/* compare roots */
		return XMSSUtil.compareByteArray(rootNode.getValue(), pubKey.getRoot());
	}
	
	/**
	 * Export XMSS^MT private key.
	 * @return XMSS^MT private key.
	 */
	public byte[] exportPrivateKey() {
		return privateKey.toByteArray();
	}

	/**
	 * Export XMSS^MT public key.
	 * @return XMSS^MT public key.
	 */
	public byte[] exportPublicKey() {
		return publicKey.toByteArray();
	}
	
	/**
	 * Export XMSS^MT BDS state.
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

	protected byte[] getPublicSeed() {
		return privateKey.getPublicSeed();
	}
	
	protected Map<Integer, BDS> getBDS() {
		return bdsState;
	}
	
	protected XMSS getXMSS() {
		return xmss;
	}
}
