package org.bouncycastle.pqc.crypto.xmss;

/**
 * WOTS+ private key.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class WOTSPlusPrivateKey {

	private WOTSPlusParameters params;
	private byte[][] privateKey;
	
	protected WOTSPlusPrivateKey(WOTSPlusParameters params) {
		super();
		if (params == null) {
			throw new NullPointerException("params == null");
		}
		this.params = params;
		privateKey = new byte[params.getLen()][params.getDigestSize()];
	}
	
	public byte[][] getPrivateKey() {
		return privateKey;
	}
	
	public void setPrivateKey(byte[][] privateKey) {
		if (privateKey == null) {
			throw new NullPointerException("privateKey == null");
		}
		if (XMSSUtil.hasNullPointer(privateKey)) {
			throw new NullPointerException("privateKey byte array == null");
		}
		if (privateKey.length != params.getLen()) {
			throw new IllegalArgumentException("wrong privateKey format");
		}
		for (int i = 0; i < privateKey.length; i++) {
			if (privateKey[i].length != params.getDigestSize()) {
				throw new IllegalArgumentException("wrong privateKey format");
			}
		}
		this.privateKey = privateKey;
	}

	public byte[][] toByteArray() {
		return XMSSUtil.cloneArray(privateKey);
	}
}
