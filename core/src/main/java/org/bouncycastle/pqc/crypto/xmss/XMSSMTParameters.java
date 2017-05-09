package org.bouncycastle.pqc.crypto.xmss;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;

/**
 * XMSS^MT Parameters.
 *
 */
public final class XMSSMTParameters {

	private final XMSSOid oid;
	private final XMSS xmss;
	private final int height;
	private final int layers;

	/**
	 * XMSSMT constructor...
	 * 
	 * @param height
	 *            Height of tree.
	 * @param layers
	 *            Amount of layers.
	 * @param digest
	 *            Digest to use.
	 * @param prng
	 *            Secure random to use.
	 */
	public XMSSMTParameters(int height, int layers, Digest digest, SecureRandom prng) {
		super();
		this.height = height;
		this.layers = layers;
		this.xmss = new XMSS(new XMSSParameters(xmssTreeHeight(height, layers), digest, prng));
		oid = DefaultXMSSMTOid.lookup(getDigest().getAlgorithmName(), getDigestSize(), getWinternitzParameter(),
				getLen(), getHeight(), layers);
		/*
		 * if (oid == null) { throw new InvalidParameterException(); }
		 */
	}

	private static int xmssTreeHeight(int height, int layers) throws IllegalArgumentException {
		if (height < 2) {
			throw new IllegalArgumentException("totalHeight must be > 1");
		}
		if (height % layers != 0) {
			throw new IllegalArgumentException("layers must divide totalHeight without remainder");
		}
		if (height / layers == 1) {
			throw new IllegalArgumentException("height / layers must be greater than 1");
		}
		return height / layers;
	}

	/**
	 * Getter height.
	 * 
	 * @return XMSSMT height.
	 */
	public int getHeight() {
		return height;
	}

	/**
	 * Getter layers.
	 * 
	 * @return XMSSMT layers.
	 */
	public int getLayers() {
		return layers;
	}

	protected XMSS getXMSS() {
		return xmss;
	}

	protected WOTSPlus getWOTSPlus() {
		return xmss.getWOTSPlus();
	}

	protected Digest getDigest() {
		return xmss.getParams().getDigest();
	}

	/**
	 * Getter digest size.
	 * 
	 * @return Digest size.
	 */
	public int getDigestSize() {
		return xmss.getParams().getDigestSize();
	}

	/**
	 * Getter Winternitz parameter.
	 * 
	 * @return Winternitz parameter.
	 */
	public int getWinternitzParameter() {
		return xmss.getParams().getWinternitzParameter();
	}

	protected int getLen() {
		return xmss.getWOTSPlus().getParams().getLen();
	}
}
