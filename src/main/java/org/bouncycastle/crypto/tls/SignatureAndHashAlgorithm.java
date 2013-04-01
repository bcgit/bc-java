package org.bouncycastle.crypto.tls;

/**
 * RFC 5246 7.4.1.4.1
 */
public class SignatureAndHashAlgorithm {

    private short hash;
    private short signature;

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

    public short getHash() {
        return hash;
    }

    public short getSignature() {
        return signature;
    }
}
