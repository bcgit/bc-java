package org.bouncycastle.pqc.crypto.xmss;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;

/**
 * XMSS Parameters.
 *
 */
public final class XMSSParameters {

	private final XMSSOid oid;
	private final WOTSPlus wotsPlus;
	private final SecureRandom prng;
	private final int height;
	private final int k;

	/**
	 * XMSS Constructor...
	 *
	 * @param height
	 *            Height of tree.
	 * @param digest
	 *            Digest to use.
	 * @param prng
	 *            Secure random to use.
	 */
	public XMSSParameters(int height, Digest digest, SecureRandom prng) {
		super();
		if (height < 2) {
			throw new IllegalArgumentException("height must be >= 2");
		}
		if (digest == null) {
			throw new NullPointerException("digest == null");
		}
		if (prng == null) {
			throw new NullPointerException("prng == null");
		}
		wotsPlus = new WOTSPlus(new WOTSPlusParameters(digest));
		this.prng = prng;
		this.height = height;
		this.k = determineMinK();
		oid = DefaultXMSSOid.lookup(getDigest().getAlgorithmName(), getDigestSize(), getWinternitzParameter(),
				wotsPlus.getParams().getLen(), height);
		/*
		 * if (oid == null) { throw new InvalidParameterException(); }
		 */
	}

	private int determineMinK() {
		for (int k = 2; k <= height; k++) {
			if ((height - k) % 2 == 0) {
				return k;
			}
		}
		throw new IllegalStateException("should never happen...");
	}

	protected Digest getDigest() {
		return wotsPlus.getParams().getDigest();
	}

	protected SecureRandom getPRNG() {
		return prng;
	}

	/**
	 * Getter digest size.
	 * 
	 * @return Digest size.
	 */
	public int getDigestSize() {
		return wotsPlus.getParams().getDigestSize();
	}

	/**
	 * Getter Winternitz parameter.
	 * 
	 * @return Winternitz parameter.
	 */
	public int getWinternitzParameter() {
		return wotsPlus.getParams().getWinternitzParameter();
	}

	/**
	 * Getter height.
	 * 
	 * @return XMSS height.
	 */
	public int getHeight() {
		return height;
	}

	protected WOTSPlus getWOTSPlus() {
		return wotsPlus;
	}

	protected int getK() {
		return k;
	}
}
