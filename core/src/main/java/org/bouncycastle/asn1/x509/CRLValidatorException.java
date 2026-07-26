package org.bouncycastle.asn1.x509;

public class CRLValidatorException
    extends Exception
{
    public CRLValidatorException(String msg)
    {
        super(msg);
    }

    public CRLValidatorException(String msg, Throwable cause)
    {
        super(msg, cause);
    }
}
