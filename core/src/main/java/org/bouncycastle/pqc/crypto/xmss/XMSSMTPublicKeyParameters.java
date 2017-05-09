package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;

/**
 * XMSSMT Public Key.
 *
 */
public final class XMSSMTPublicKeyParameters implements XMSSStoreableObjectInterface {

	private final XMSSMTParameters params;
	// private final int oid;
	private final byte[] root;
	private final byte[] publicSeed;

	private XMSSMTPublicKeyParameters(Builder builder) throws ParseException {
		super();
		params = builder.params;
		if (params == null) {
			throw new NullPointerException("params == null");
		}
		int n = params.getDigestSize();
		byte[] publicKey = builder.publicKey;
		if (publicKey != null) {
			/* import */
			// int oidSize = 4;
			int rootSize = n;
			int publicSeedSize = n;
			int totalSize = rootSize + publicSeedSize;
			if (publicKey.length != totalSize) {
				throw new ParseException("public key has wrong size", 0);
			}
			int position = 0;
			/*
			 * oid = XMSSUtil.bytesToIntBigEndian(in, position); if (oid !=
			 * params.getOid().getOid()) { throw new ParseException("wrong oid",
			 * 0); } position += oidSize;
			 */
			root = XMSSUtil.extractBytesAtOffset(publicKey, position, rootSize);
			position += rootSize;
			publicSeed = XMSSUtil.extractBytesAtOffset(publicKey, position, publicSeedSize);
		} else {
			/* set */
			byte[] tmpRoot = builder.root;
			if (tmpRoot != null) {
				if (tmpRoot.length != n) {
					throw new IllegalArgumentException("length of root must be equal to length of digest");
				}
				root = tmpRoot;
			} else {
				root = new byte[n];
			}
			byte[] tmpPublicSeed = builder.publicSeed;
			if (tmpPublicSeed != null) {
				if (tmpPublicSeed.length != n) {
					throw new IllegalArgumentException("length of publicSeed must be equal to length of digest");
				}
				publicSeed = tmpPublicSeed;
			} else {
				publicSeed = new byte[n];
			}
		}
	}

	public static class Builder {

		/* mandatory */
		private final XMSSMTParameters params;
		/* optional */
		private byte[] root = null;
		private byte[] publicSeed = null;
		private byte[] publicKey = null;

		public Builder(XMSSMTParameters params) {
			super();
			this.params = params;
		}

		public Builder withRoot(byte[] val) {
			root = XMSSUtil.cloneArray(val);
			return this;
		}

		public Builder withPublicSeed(byte[] val) {
			publicSeed = XMSSUtil.cloneArray(val);
			return this;
		}

		public Builder withPublicKey(byte[] val) {
			publicKey = XMSSUtil.cloneArray(val);
			return this;
		}

		public XMSSMTPublicKeyParameters build() throws ParseException {
			return new XMSSMTPublicKeyParameters(this);
		}
	}

	public byte[] toByteArray() {
		/* oid || root || seed */
		int n = params.getDigestSize();
		// int oidSize = 4;
		int rootSize = n;
		int publicSeedSize = n;
		int totalSize = rootSize + publicSeedSize;
		// int totalSize = oidSize + rootSize + publicSeedSize;
		byte[] out = new byte[totalSize];
		int position = 0;
		/* copy oid */
		/*
		 * XMSSUtil.intToBytesBigEndianOffset(out, oid, position); position +=
		 * oidSize;
		 */
		/* copy root */
		XMSSUtil.copyBytesAtOffset(out, root, position);
		position += rootSize;
		/* copy public seed */
		XMSSUtil.copyBytesAtOffset(out, publicSeed, position);
		return out;
	}

	public byte[] getRoot() {
		return XMSSUtil.cloneArray(root);
	}

	public byte[] getPublicSeed() {
		return XMSSUtil.cloneArray(publicSeed);
	}
}
