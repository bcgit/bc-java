package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.Digest;

/**
 * Buffers input until the hash algorithm is determined.
 */
class DeferredHash implements TlsDigest {

    private ByteArrayOutputStream buf = new ByteArrayOutputStream();
    private short hashAlgorithm = -1;
    private Digest hash = null;

    DeferredHash() {
        this.buf = new ByteArrayOutputStream();
        this.hash = null;
    }

    private DeferredHash(Digest hash) {
        this.buf = null;
        this.hash = hash;
    }

    void setHashAlgorithm(short hashAlgorithm) {

        this.hashAlgorithm = hashAlgorithm;
        this.hash = TlsUtils.createHash(hashAlgorithm);

        byte[] data = buf.toByteArray();
        this.hash.update(data, 0, data.length);
        this.buf = null;
    }

    public TlsDigest fork() {
        checkHash();
        return new DeferredHash(TlsUtils.cloneHash(hashAlgorithm, hash));
    }

    public String getAlgorithmName() {
        checkHash();
        return hash.getAlgorithmName();
    }

    public int getDigestSize() {
        checkHash();
        return hash.getDigestSize();
    }

    public void update(byte input) {
        if (hash == null) {
            buf.write(input);
        } else {
            hash.update(input);
        }
    }

    public void update(byte[] input, int inOff, int len) {
        if (hash == null) {
            buf.write(input, inOff, len);
        } else {
            hash.update(input, inOff, len);
        }
    }

    public int doFinal(byte[] output, int outOff) {
        checkHash();
        return hash.doFinal(output, outOff);
    }

    public void reset() {
        if (hash == null) {
            buf.reset();
        } else {
            hash.reset();
        }
    }

    protected void checkHash() {
        if (hash == null) {
            throw new IllegalStateException("No hash algorithm has been set");
        }
    }
}
