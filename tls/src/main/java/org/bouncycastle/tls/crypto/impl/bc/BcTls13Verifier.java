package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.io.SignerOutputStream;
import org.bouncycastle.tls.crypto.Tls13Verifier;

final class BcTls13Verifier
    implements Tls13Verifier
{
    private final SignerOutputStream output;

    BcTls13Verifier(Signer verifier)
    {
        if (verifier == null)
        {
            throw new NullPointerException("'verifier' cannot be null");
        }

        this.output = new SignerOutputStream(verifier);
    }

    public final OutputStream getOutputStream() throws IOException
    {
        return output;
    }

    public final boolean verifySignature(byte[] signature) throws IOException
    {
        return output.getSigner().verifySignature(signature);
    }
}
