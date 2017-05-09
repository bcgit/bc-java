package org.bouncycastle.pqc.crypto.xmss;

import java.io.IOException;
import java.text.ParseException;

import org.bouncycastle.util.Pack;

/**
 * XMSS Private Key.
 *
 */
public final class XMSSPrivateKeyParameters implements XMSSStoreableObjectInterface {

	/**
	 * XMSS parameters object.
	 */
	private final XMSSParameters params;
	/**
	 * Index for WOTS+ keys (randomization factor).
	 */
	private final int index;
	/**
	 * Secret for the derivation of WOTS+ secret keys.
	 */
	private final byte[] secretKeySeed;
	/**
	 * Secret for the randomization of message digests during signature
	 * creation.
	 */
	private final byte[] secretKeyPRF;
	/**
	 * Public seed for the randomization of hashes.
	 */
	private final byte[] publicSeed;
	/**
	 * Public root of binary tree.
	 */
	private final byte[] root;
	/**
	 * BDS state.
	 */
	private final BDS bdsState;

	private XMSSPrivateKeyParameters(Builder builder) throws ParseException, ClassNotFoundException, IOException {
		super();
		params = builder.params;
		if (params == null) {
			throw new NullPointerException("params == null");
		}
		int n = params.getDigestSize();
		byte[] privateKey = builder.privateKey;
		if (privateKey != null) {
			if (builder.xmss == null) {
				throw new NullPointerException("xmss == null");
			}
			/* import */
			int height = params.getHeight();
			int indexSize = 4;
			int secretKeySize = n;
			int secretKeyPRFSize = n;
			int publicSeedSize = n;
			int rootSize = n;
			/*
			int totalSize = indexSize + secretKeySize + secretKeyPRFSize + publicSeedSize + rootSize;
			if (privateKey.length != totalSize) {
				throw new ParseException("private key has wrong size", 0);
			}
			*/
			int position = 0;
			index = Pack.bigEndianToInt(privateKey, position);
			if (!XMSSUtil.isIndexValid(height, index)) {
				throw new ParseException("index out of bounds", 0);
			}
			position += indexSize;
			secretKeySeed = XMSSUtil.extractBytesAtOffset(privateKey, position, secretKeySize);
			position += secretKeySize;
			secretKeyPRF = XMSSUtil.extractBytesAtOffset(privateKey, position, secretKeyPRFSize);
			position += secretKeyPRFSize;
			publicSeed = XMSSUtil.extractBytesAtOffset(privateKey, position, publicSeedSize);
			position += publicSeedSize;
			root = XMSSUtil.extractBytesAtOffset(privateKey, position, rootSize);
			position += rootSize;
			/* import BDS state */
			byte[] bdsStateBinary = XMSSUtil.extractBytesAtOffset(privateKey, position, privateKey.length - position);
			BDS bdsImport = (BDS) XMSSUtil.deserialize(bdsStateBinary);
			bdsImport.setXMSS(builder.xmss);
			bdsImport.validate();
			bdsState = bdsImport;
		} else {
			/* set */
			index = builder.index;
			byte[] tmpSecretKeySeed = builder.secretKeySeed;
			if (tmpSecretKeySeed != null) {
				if (tmpSecretKeySeed.length != n) {
					throw new IllegalArgumentException("size of secretKeySeed needs to be equal size of digest");
				}
				secretKeySeed = tmpSecretKeySeed;
			} else {
				secretKeySeed = new byte[n];
			}
			byte[] tmpSecretKeyPRF = builder.secretKeyPRF;
			if (tmpSecretKeyPRF != null) {
				if (tmpSecretKeyPRF.length != n) {
					throw new IllegalArgumentException("size of secretKeyPRF needs to be equal size of digest");
				}
				secretKeyPRF = tmpSecretKeyPRF;
			} else {
				secretKeyPRF = new byte[n];
			}
			byte[] tmpPublicSeed = builder.publicSeed;
			if (tmpPublicSeed != null) {
				if (tmpPublicSeed.length != n) {
					throw new IllegalArgumentException("size of publicSeed needs to be equal size of digest");
				}
				publicSeed = tmpPublicSeed;
			} else {
				publicSeed = new byte[n];
			}
			byte[] tmpRoot = builder.root;
			if (tmpRoot != null) {
				if (tmpRoot.length != n) {
					throw new IllegalArgumentException("size of root needs to be equal size of digest");
				}
				root = tmpRoot;
			} else {
				root = new byte[n];
			}
			BDS tmpBDSState = builder.bdsState;
			if (tmpBDSState != null) {
				bdsState = tmpBDSState;
			} else {
				bdsState = new BDS(new XMSS(params));
			}
		}
	}

	public static class Builder {

		/* mandatory */
		private final XMSSParameters params;
		/* optional */
		private int index = 0;
		private byte[] secretKeySeed = null;
		private byte[] secretKeyPRF = null;
		private byte[] publicSeed = null;
		private byte[] root = null;
		private BDS bdsState = null;
		private byte[] privateKey = null;
		private XMSS xmss = null;

		public Builder(XMSSParameters params) {
			super();
			this.params = params;
		}

		public Builder withIndex(int val) {
			index = val;
			return this;
		}

		public Builder withSecretKeySeed(byte[] val) {
			secretKeySeed = XMSSUtil.cloneArray(val);
			return this;
		}
		
		public Builder withSecretKeyPRF(byte[] val) {
			secretKeyPRF = XMSSUtil.cloneArray(val);
			return this;
		}

		public Builder withPublicSeed(byte[] val) {
			publicSeed = XMSSUtil.cloneArray(val);
			return this;
		}

		public Builder withRoot(byte[] val) {
			root = XMSSUtil.cloneArray(val);
			return this;
		}

		public Builder withBDSState(BDS valBDS) {
			bdsState = valBDS;
			return this;
		}

		public Builder withPrivateKey(byte[] privateKeyVal, XMSS xmssVal) {
			privateKey = XMSSUtil.cloneArray(privateKeyVal);
			xmss = xmssVal;
			return this;
		}

		public XMSSPrivateKeyParameters build() throws ParseException, ClassNotFoundException, IOException {
			return new XMSSPrivateKeyParameters(this);
		}
	}

	public byte[] toByteArray() {
		/* index || secretKeySeed || secretKeyPRF || publicSeed || root */
		int n = params.getDigestSize();
		int indexSize = 4;
		int secretKeySize = n;
		int secretKeyPRFSize = n;
		int publicSeedSize = n;
		int rootSize = n;
		int totalSize = indexSize + secretKeySize + secretKeyPRFSize + publicSeedSize + rootSize;
		byte[] out = new byte[totalSize];
		int position = 0;
		/* copy index */
		XMSSUtil.intToBytesBigEndianOffset(out, index, position);
		position += indexSize;
		/* copy secretKeySeed */
		XMSSUtil.copyBytesAtOffset(out, secretKeySeed, position);
		position += secretKeySize;
		/* copy secretKeyPRF */
		XMSSUtil.copyBytesAtOffset(out, secretKeyPRF, position);
		position += secretKeyPRFSize;
		/* copy publicSeed */
		XMSSUtil.copyBytesAtOffset(out, publicSeed, position);
		position += publicSeedSize;
		/* copy root */
		XMSSUtil.copyBytesAtOffset(out, root, position);
		/* concatenate bdsState */
		byte[] bdsStateOut = null;
		try {
			bdsStateOut = XMSSUtil.serialize(bdsState);
		} catch (IOException e) {
			e.printStackTrace();
			throw new RuntimeException("error serializing bds state");
		}
		return XMSSUtil.concat(out, bdsStateOut);
	}

	public int getIndex() {
		return index;
	}

	public byte[] getSecretKeySeed() {
		return XMSSUtil.cloneArray(secretKeySeed);
	}

	public byte[] getSecretKeyPRF() {
		return XMSSUtil.cloneArray(secretKeyPRF);
	}

	public byte[] getPublicSeed() {
		return XMSSUtil.cloneArray(publicSeed);
	}

	public byte[] getRoot() {
		return XMSSUtil.cloneArray(root);
	}
	
	public BDS getBDSState() {
		return bdsState;
	}
}
