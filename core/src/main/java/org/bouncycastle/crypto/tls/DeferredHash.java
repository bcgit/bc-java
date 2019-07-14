package org.bouncycastle.crypto.tls;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Shorts;

import java.util.Hashtable;

class DeferredHash implements TlsHandshakeHash {

	protected static final int BUFFERING_HASH_LIMIT = 4;

	protected TlsContext context;

	private DigestInputBuffer buf = new DigestInputBuffer();
	private Short prfHashAlgorithm;
	private Hashtable<Short, Digest> hashes = new Hashtable<>();

	DeferredHash() {
	}

	private DeferredHash(Short prfHashAlgorithm, Digest prfHash) {
		this.buf = null;
		this.prfHashAlgorithm = prfHashAlgorithm;
		this.hashes.put(prfHashAlgorithm, prfHash);
	}

	public void init(TlsContext context) {
		this.context = context;
	}

	public TlsHandshakeHash notifyPRFDetermined() {
		int prfAlgorithm = this.context.getSecurityParameters().getPrfAlgorithm();
		if (prfAlgorithm == 0) {
			CombinedHash legacyHash = new CombinedHash();
			legacyHash.init(this.context);
			this.buf.updateDigest(legacyHash);

			return legacyHash.notifyPRFDetermined();

		} else {
			this.prfHashAlgorithm = Shorts.valueOf(TlsUtils.getHashAlgorithmForPRFAlgorithm(prfAlgorithm));
			this.checkTrackingHash(this.prfHashAlgorithm);

			return this;
		}
	}

	public void trackHashAlgorithm(short hashAlgorithm) {
		if (this.buf == null) {
			throw new IllegalStateException("Too late to track more hash algorithms");
		} else {
			this.checkTrackingHash(Shorts.valueOf(hashAlgorithm));
		}
	}

	public void sealHashAlgorithms() {
		this.checkStopBuffering();
	}

	public TlsHandshakeHash stopTracking() {
		Digest prfHash = TlsUtils.cloneHash(this.prfHashAlgorithm, this.hashes.get(this.prfHashAlgorithm));
		if (this.buf != null) {
			this.buf.updateDigest(prfHash);
		}

		DeferredHash result = new DeferredHash(this.prfHashAlgorithm, prfHash);
		result.init(this.context);

		return result;
	}

	public Digest forkPRFHash() {
		this.checkStopBuffering();
		if (this.buf != null) {
			Digest prfHash = TlsUtils.createHash(this.prfHashAlgorithm);
			this.buf.updateDigest(prfHash);

			return prfHash;
		} else {
			return TlsUtils.cloneHash(this.prfHashAlgorithm, this.hashes.get(this.prfHashAlgorithm));
		}
	}

	public byte[] getFinalHash(short hashAlgorithm) {
		Digest d = this.hashes.get(Shorts.valueOf(hashAlgorithm));

		if (d == null) {
			throw new IllegalStateException("HashAlgorithm." + HashAlgorithm.getText(hashAlgorithm) + " is not being tracked");
		}

		d = TlsUtils.cloneHash(hashAlgorithm, d);
		if (this.buf != null) {
			this.buf.updateDigest(d);
		}

		byte[] bs = new byte[d.getDigestSize()];
		d.doFinal(bs, 0);

		return bs;
	}

	public String getAlgorithmName() {
		throw new IllegalStateException("Use fork() to get a definite Digest");
	}

	public int getDigestSize() {
		throw new IllegalStateException("Use fork() to get a definite Digest");
	}

	public void update(byte input) {
		if (this.buf != null) {
			this.buf.write(input);
		} else {

			this.hashes.values().forEach(hash -> hash.update(input));
		}
	}

	public void update(byte[] input, int inOff, int len) {
		if (this.buf != null) {
			this.buf.write(input, inOff, len);
		} else {
			this.hashes.values().forEach(hash -> hash.update(input, inOff, len));
		}
	}

	public int doFinal(byte[] output, int outOff) {
		throw new IllegalStateException("Use fork() to get a definite Digest");
	}

	public void reset() {
		if (this.buf != null) {
			this.buf.reset();
		} else {
			this.hashes.values().forEach(Digest::reset);
		}
	}

	protected void checkStopBuffering() {
		if (this.buf != null && this.hashes.size() <= 4) {

			this.hashes.values().forEach(buf::updateDigest);

			this.buf = null;
		}
	}

	protected void checkTrackingHash(Short hashAlgorithm) {
		if (!this.hashes.containsKey(hashAlgorithm) && !"UNKNOWN".equals(HashAlgorithm.getName(hashAlgorithm))) {
			Digest hash = TlsUtils.createHash(hashAlgorithm);
			this.hashes.put(hashAlgorithm, hash);
		}
	}
}
