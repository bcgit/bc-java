package org.bouncycastle.operator;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

/**
 * ContentSigner for "Unsigned X.509 Certificates"
 */
public class NoSignatureContentSigner
    implements ContentSigner
{
    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return new AlgorithmIdentifier(X509ObjectIdentifiers.id_alg_noSignature, DERNull.INSTANCE);
    }

    @Override
    public OutputStream getOutputStream()
    {
        return new OutputStream()
        {
            @Override
            public void write(byte[] buf, int off, int len)
                throws IOException
            {
                // do nothing
            }

            @Override
            public void write(int i)
                throws IOException
            {
                // do nothing
            }
        };
    }

    @Override
    public byte[] getSignature()
    {
        return new byte[0];
    }
}
