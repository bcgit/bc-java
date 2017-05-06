package org.bouncycastle.pqc.crypto.xmss;

import java.io.IOException;
import java.text.ParseException;
import java.util.Map;
import java.util.TreeMap;

/**
 * XMSSMT Private Key.
 *
 */
public final class XMSSMTPrivateKeyParameters implements XMSSStoreableObjectInterface {

	private final XMSSMTParameters params;
	private final long index;
	private final byte[] secretKeySeed;
	private final byte[] secretKeyPRF;
	private final byte[] publicSeed;
	private final byte[] root;
	private final Map<Integer, BDS> bdsState;

	private XMSSMTPrivateKeyParameters(Builder builder) throws ParseException, ClassNotFoundException, IOException {
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
			int totalHeight = params.getHeight();
			int indexSize = (int) Math.ceil(totalHeight / (double) 8);
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
			index = XMSSUtil.bytesToXBigEndian(privateKey, position, indexSize);
			if (!XMSSUtil.isIndexValid(totalHeight, index)) {
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
			@SuppressWarnings("unchecked")
			Map<Integer, BDS> bdsImport = (TreeMap<Integer, BDS>) XMSSUtil.deserialize(bdsStateBinary);
			for (Integer key : bdsImport.keySet()) {
				BDS bds = bdsImport.get(key);
				bds.setXMSS(builder.xmss);
				bds.validate();
			}
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
			Map<Integer, BDS> tmpBDSState = builder.bdsState;
			if (tmpBDSState != null) {
				bdsState = tmpBDSState;
			} else {
				bdsState = new TreeMap<Integer, BDS>();
			}
		}
	}

	public static class Builder {

		/* mandatory */
		private final XMSSMTParameters params;
		/* optional */
		private long index = 0L;
		private byte[] secretKeySeed = null;
		private byte[] secretKeyPRF = null;
		private byte[] publicSeed = null;
		private byte[] root = null;
		private Map<Integer, BDS> bdsState = null;
		private byte[] privateKey = null;
		private XMSS xmss = null;

		public Builder(XMSSMTParameters params) {
			super();
			this.params = params;
		}

		public Builder withIndex(long val) {
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

		public Builder withBDSState(Map<Integer, BDS> val) {
			bdsState = val;
			return this;
		}

		public Builder withPrivateKey(byte[] privateKeyVal, XMSS xmssVal) {
			privateKey = XMSSUtil.cloneArray(privateKeyVal);
			xmss = xmssVal;
			return this;
		}

		public XMSSMTPrivateKeyParameters build() throws ParseException, ClassNotFoundException, IOException {
			return new XMSSMTPrivateKeyParameters(this);
		}
	}

	public byte[] toByteArray() {
		/* index || secretKeySeed || secretKeyPRF || publicSeed || root */
		int n = params.getDigestSize();
		int indexSize = (int) Math.ceil(params.getHeight() / (double) 8);
		int secretKeySize = n;
		int secretKeyPRFSize = n;
		int publicSeedSize = n;
		int rootSize = n;
		int totalSize = indexSize + secretKeySize + secretKeyPRFSize + publicSeedSize + rootSize;
		byte[] out = new byte[totalSize];
		int position = 0;
		/* copy index */
		byte[] indexBytes = XMSSUtil.toBytesBigEndian(index, indexSize);
		XMSSUtil.copyBytesAtOffset(out, indexBytes, position);
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

	/*
	protected void increaseIndex(XMSSMT mt) {
		if (mt == null) {
			throw new NullPointerException("mt == null");
		}
		ZonedDateTime currentTime = ZonedDateTime.now(ZoneOffset.UTC);
		long differenceHours = Duration.between(lastUsage, currentTime).toHours();
		if (differenceHours >= 24) {
			mt.getXMSS().setPublicSeed(getPublicSeed());

			Map<Integer, BDS> bdsStates = mt.getBDS();
			int xmssHeight = params.getXMSS().getParams().getHeight();
			long keyIncreaseCount = differenceHours * indexIncreaseCountPerHour;
			long oldGlobalIndex = getIndex();
			long newGlobalIndex = oldGlobalIndex + keyIncreaseCount;
			long oldIndexTree = XMSSUtil.getTreeIndex(oldGlobalIndex, xmssHeight);
			long newIndexTree = XMSSUtil.getTreeIndex(newGlobalIndex, xmssHeight);
			int newIndexLeaf = XMSSUtil.getLeafIndex(newGlobalIndex, xmssHeight);

			// adjust bds instances
			for (int layer = 0; layer < params.getLayers(); layer++) {
				OTSHashAddress otsHashAddress = new OTSHashAddress();
				otsHashAddress.setLayerAddress(layer);
				otsHashAddress.setTreeAddress(newIndexTree);

				if (newIndexLeaf != 0) {
					if (oldIndexTree != newIndexTree || bdsStates.get(layer) == null) {
						bdsStates.put(layer, new BDS(mt.getXMSS()));
						bdsStates.get(layer).initialize(otsHashAddress);
					}
					for (int indexLeaf = bdsStates.get(layer).getIndex(); indexLeaf < newIndexLeaf; indexLeaf++) {
						if (indexLeaf < ((1 << xmssHeight) - 1)) {
							bdsStates.get(layer).nextAuthenticationPath(otsHashAddress);
						}
					}
				}
				oldIndexTree = XMSSUtil.getTreeIndex(oldIndexTree, xmssHeight);
				newIndexLeaf = XMSSUtil.getLeafIndex(newIndexTree, xmssHeight);
				newIndexTree = XMSSUtil.getTreeIndex(newIndexTree, xmssHeight);
			}
			setIndex(newGlobalIndex);
		}
	}
	*/

	public long getIndex() {
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
	
	public Map<Integer, BDS> getBDSState() {
		return bdsState;
	}
}
