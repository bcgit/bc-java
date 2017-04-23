package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.crypto.Digest;

/**
 * WOTS+ Parameters.
 */
public final class WOTSPlusParameters {

	/**
	 * OID.
	 */
	private final XMSSOid oid;
	/**
	 * Digest used in WOTS+.
	 */
	private final Digest digest;
	/**
	 * The message digest size.
	 */
	private final int digestSize;
	/**
	 * The Winternitz parameter (currently fixed to 16).
	 */
	private final int winternitzParameter;
	/**
	 * The number of n-byte string elements in a WOTS+ secret key, public key,
	 * and signature.
	 */
	private final int len;
	/**
	 * len1.
	 */
	private final int len1;
	/**
	 * len2.
	 */
	private final int len2;

	/**
	 * Constructor...
	 *
	 * @param digest
	 *            The digest used for WOTS+.
	 */
	protected WOTSPlusParameters(Digest digest) {
		super();
		if (digest == null) {
			throw new NullPointerException("digest == null");
		}
		this.digest = digest;
		digestSize = XMSSUtil.getDigestSize(digest);
		winternitzParameter = 16;
		len1 = (int) Math.ceil((double) (8 * digestSize) / XMSSUtil.log2(winternitzParameter));
		len2 = (int) Math.floor(XMSSUtil.log2(len1 * (winternitzParameter - 1)) / XMSSUtil.log2(winternitzParameter))
				+ 1;
		len = len1 + len2;
		oid = WOTSPlusOid.lookup(digest.getAlgorithmName(), digestSize, winternitzParameter, len);
		if (oid == null) {
			throw new IllegalArgumentException("cannot find OID for digest algorithm: " + digest.getAlgorithmName());
		}
	}

	/**
	 * Getter OID.
	 *
	 * @return WOTS+ OID.
	 */
	protected XMSSOid getOid() {
		return oid;
	}

	/**
	 * Getter digest.
	 *
	 * @return digest.
	 */
	protected Digest getDigest() {
		return digest;
	}

	/**
	 * Getter digestSize.
	 *
	 * @return digestSize.
	 */
	protected int getDigestSize() {
		return digestSize;
	}

	/**
	 * Getter WinternitzParameter.
	 *
	 * @return winternitzParameter.
	 */
	protected int getWinternitzParameter() {
		return winternitzParameter;
	}

	/**
	 * Getter len.
	 *
	 * @return len.
	 */
	protected int getLen() {
		return len;
	}

	/**
	 * Getter len1.
	 *
	 * @return len1.
	 */
	protected int getLen1() {
		return len1;
	}

	/**
	 * Getter len2.
	 *
	 * @return len2.
	 */
	protected int getLen2() {
		return len2;
	}
}
