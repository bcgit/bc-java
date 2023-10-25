package org.bouncycastle.tls.injection.sigalgs;

import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;

import java.io.IOException;

public class MyTlsSigner implements TlsSigner
{
    private JcaTlsCrypto crypto;
    private SignerFunction fn;
    private byte[] key;

    public MyTlsSigner(JcaTlsCrypto crypto, byte[] key, SignerFunction fn) {
        this.crypto = crypto;
        this.fn = fn;
        this.key = key;
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash)
            throws IOException {
        try {
            return this.fn.sign(this.crypto, hash, key);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) throws IOException {
        return new MyStreamSigner(this.crypto, key, this.fn);
    }
}