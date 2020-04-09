package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.io.SignerOutputStream;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.util.io.TeeOutputStream;

class BcVerifyingStreamSigner
    implements TlsStreamSigner
{
    private final Signer signer;
    private final Signer verifier;
    private final TeeOutputStream output;

    BcVerifyingStreamSigner(Signer signer, Signer verifier)
    {
        OutputStream outputSigner = new SignerOutputStream(signer);
        OutputStream outputVerifier = new SignerOutputStream(verifier);

        this.signer = signer;
        this.verifier = verifier;
        this.output = new TeeOutputStream(outputSigner, outputVerifier);
    }

    public OutputStream getOutputStream() throws IOException
    {
        return output;
    }

    public byte[] getSignature() throws IOException
    {
        try
        {
            byte[] signature = signer.generateSignature();
            if (verifier.verifySignature(signature))
            {
                return signature;
            }
        }
        catch (CryptoException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }

        throw new TlsFatalAlert(AlertDescription.internal_error);
    }
}
