package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.io.SignerOutputStream;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;

class BcTlsStreamVerifier
    implements TlsStreamVerifier
{
    private final SignerOutputStream output;
    private final byte[] signature;

    BcTlsStreamVerifier(Signer verifier, byte[] signature)
    {
        this.output = new SignerOutputStream(verifier);
        this.signature = signature;
    }

    public OutputStream getOutputStream() throws IOException
    {
        return output;
    }

    public boolean isVerified() throws IOException
    {
        return output.getSigner().verifySignature(signature);
    }
}
