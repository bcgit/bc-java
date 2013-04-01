package org.bouncycastle.crypto.tls;

/**
 * RFC 5246 7.4.1.4.1
 */
public class SignatureAndHashAlgorithm {

    private short hash;
    private short signature;

    /**
     * @param hash
     *            {@link HashAlgorithm}
     * @param signature
     *            {@link SignatureAlgorithm}
     */
    public SignatureAndHashAlgorithm(short hash, short signature) {

        if (!TlsUtils.isValidUint8(hash)) {
            throw new IllegalArgumentException("'hash' should be a uint8");
        }
        if (!TlsUtils.isValidUint8(signature)) {
            throw new IllegalArgumentException("'signature' should be a uint8");
        }

        this.hash = hash;
        this.signature = signature;
    }

    /**
     * @return {@link HashAlgorithm}
     */
    public short getHash() {
        return hash;
    }

    /**
     * @return {@link SignatureAlgorithm}
     */
    public short getSignature() {
        return signature;
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof SignatureAndHashAlgorithm)) {
            return false;
        }
        SignatureAndHashAlgorithm other = (SignatureAndHashAlgorithm) obj;
        return other.getHash() == getHash() && other.getSignature() == getSignature();
    }

    public int hashCode() {
        return (getHash() << 8) | getSignature();
    }
}
