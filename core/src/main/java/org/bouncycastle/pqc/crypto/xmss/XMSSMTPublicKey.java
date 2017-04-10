package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;

/**
 * XMSSMT Public Key.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSMTPublicKey implements XMSSStoreableObjectInterface {
	
	private int oid;
	private byte[] root;
	private byte[] publicSeed;
	private XMSSMTParameters params;
	
	public XMSSMTPublicKey(XMSSMTParameters params) {
		super();
		if (params == null) {
			throw new NullPointerException("params == null");
		}	
		this.params = params;
		int n = params.getDigestSize();
		root = new byte[n];
		publicSeed = new byte[n];
	}
	
	public byte[] toByteArray() {
		/* oid || root || seed */
		int n = params.getDigestSize();
		//int oidSize = 4;
		int rootSize = n;
		int publicSeedSize = n;
		int totalSize = rootSize + publicSeedSize;
		//int totalSize = oidSize + rootSize + publicSeedSize;
		byte[] out = new byte[totalSize];
		int position = 0;
		/* copy oid */
		/*
		XMSSUtil.intToBytesBigEndianOffset(out, oid, position);
		position += oidSize;
		*/
		/* copy root */
		XMSSUtil.copyBytesAtOffset(out, root, position);
		position += rootSize;
		/* copy public seed */
		XMSSUtil.copyBytesAtOffset(out, publicSeed, position);
		return out;
	}
	
	@Override
	public void parseByteArray(byte[] in) throws ParseException {
		if (in == null) {
			throw new NullPointerException("in == null");
		}
		int n = params.getDigestSize();
		//int oidSize = 4;
		int rootSize = n;
		int publicSeedSize = n;
		int totalSize = rootSize + publicSeedSize;
		if (in.length != totalSize) {
			throw new ParseException("public key has wrong size", 0);
		}
		int position = 0;
		/*
		oid = XMSSUtil.bytesToIntBigEndian(in, position);
		if (oid != params.getOid().getOid()) {
			throw new ParseException("wrong oid", 0);
		}
		position += oidSize;
		*/
		root = XMSSUtil.extractBytesAtOffset(in, position, rootSize);
		position += rootSize;
		publicSeed = XMSSUtil.extractBytesAtOffset(in, position, publicSeedSize);
	}
	
	public byte[] getRoot() {
		return root;
	}
	
	public void setRoot(byte[] root) {
		if (root == null) {
			throw new NullPointerException("root == null");
		}
		if (root.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of root needs to be equal size of digest");
		}
		this.root = root;
	}

	public byte[] getPublicSeed() {
		return publicSeed;
	}

	public void setPublicSeed(byte[] publicSeed) {
		if (publicSeed == null) {
			throw new NullPointerException("publicSeed == null");
		}
		if (publicSeed.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of publicSeed needs to be equal size of digest");
		}
		this.publicSeed = publicSeed;
	}
}
