package org.bouncycastle.jce.exception;

import java.security.cert.CertificateEncodingException;

@Deprecated
public class ExtCertificateEncodingException
    extends CertificateEncodingException
    implements ExtException
{
    private Throwable cause;

    public ExtCertificateEncodingException(String message, Throwable cause)
    {
        super(message);
        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}
