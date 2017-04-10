package org.bouncycastle.pqc.crypto.xmss;

/**
 * WOTS+ public key.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class WOTSPlusPublicKey {

	private WOTSPlusParameters params;
	private byte[][] publicKey;
	
	protected WOTSPlusPublicKey(WOTSPlusParameters params) {
		super();
		if (params == null) {
			throw new NullPointerException("params == null");
		}
		this.params = params;
		publicKey = new byte[params.getLen()][params.getDigestSize()];
	}
	
	public byte[][] getPublicKey() {
		return publicKey;
	}
	
	public void setPublicKey(byte[][] publicKey) {
		if (publicKey == null) {
			throw new NullPointerException("publicKey == null");
		}
		if (XMSSUtil.hasNullPointer(publicKey)) {
			throw new NullPointerException("publicKey byte array == null");
		}
		if (publicKey.length != params.getLen()) {
			throw new IllegalArgumentException("wrong publicKey size");
		}
		for (int i = 0; i < publicKey.length; i++) {
			if (publicKey[i].length != params.getDigestSize()) {
				throw new IllegalArgumentException("wrong publicKey format");
			}
		}
		this.publicKey = publicKey;
	}
	
	public byte[][] toByteArray() {
		return XMSSUtil.cloneArray(publicKey);
	}
}
