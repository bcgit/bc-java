package org.bouncycastle.tls.injection.sigalgs;

import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class MyStreamSigner implements TlsStreamSigner {

    private JcaTlsCrypto crypto;

    private SignerFunction fn;
    private byte[] key;
    private ByteArrayOutputStream os = new ByteArrayOutputStream();

    public MyStreamSigner(JcaTlsCrypto crypto, byte[] key, SignerFunction fn) {
        this.crypto = crypto;
        this.fn = fn;
        this.key = key;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        return os;
    }

    @Override
    public byte[] getSignature() throws IOException {
        byte[] data = os.toByteArray();
        byte[] signature = new byte[0];
        try {
            signature = fn.sign(this.crypto, data, key);
        } catch (Exception e) {
            throw new IOException(e);
        }
        return signature;
    }
}