package org.bouncycastle.crypto.params;

import java.math.BigInteger;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;

public class CramerShoupParameters implements CipherParameters {

	private BigInteger p; // large prime
	private BigInteger q; // prime order of G with p = 2q + 1
	private BigInteger g1, g2; // generate G
	
	private Digest H; // hash function

	public CramerShoupParameters(BigInteger p, BigInteger q, BigInteger g1, BigInteger g2, Digest H) {
		this.p = p;
		this.q = q;
		this.g1 = g1;
		this.g2 = g2;
		this.H = H;
	}

	public boolean equals(Object obj) {
		if (!(obj instanceof DSAParameters)) {
			return false;
		}

		CramerShoupParameters pm = (CramerShoupParameters) obj;

		return (pm.getP().equals(p) && pm.getQ().equals(q) && pm.getG1().equals(g1) && pm.getG2().equals(g2));
	}

	public int hashCode() {
		return getP().hashCode() ^ getQ().hashCode() ^ getG1().hashCode() ^ getG2().hashCode();
	}
	
	public BigInteger getG1() {
		return g1;
	}
	
	public BigInteger getG2() {
		return g2;
	}
	
	public BigInteger getP() {
		return p;
	}
	
	public BigInteger getQ() {
		return q;
	}
	
	public Digest getH() {
		H.reset();
		return H;
	}
	
}
