package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.jcajce.io.OutputStreamFactory;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.Tls13Verifier;

final class JcaTls13Verifier
    implements Tls13Verifier
{
    private final Signature verifier;
    private final OutputStream output;

    JcaTls13Verifier(Signature verifier)
    {
        this.verifier = verifier;
        this.output = OutputStreamFactory.createStream(verifier);
    }

    public final OutputStream getOutputStream() throws IOException
    {
        return output;
    }

    public final boolean verifySignature(byte[] signature) throws IOException
    {
        try
        {
            return verifier.verify(signature);
        }
        catch (SignatureException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }
}
