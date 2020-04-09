package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.jcajce.io.OutputStreamFactory;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.util.io.TeeOutputStream;

class JcaVerifyingStreamSigner
    implements TlsStreamSigner
{
    private final Signature signer;
    private final Signature verifier;
    private final OutputStream output;

    JcaVerifyingStreamSigner(Signature signer, Signature verifier)
    {
        OutputStream outputSigner = OutputStreamFactory.createStream(signer);
        OutputStream outputVerifier = OutputStreamFactory.createStream(verifier);

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
            byte[] signature = signer.sign();
            if (verifier.verify(signature))
            {
                return signature;
            }
        }
        catch (SignatureException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }

        throw new TlsFatalAlert(AlertDescription.internal_error);
    }
}
