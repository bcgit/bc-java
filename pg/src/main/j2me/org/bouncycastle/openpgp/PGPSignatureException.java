package org.bouncycastle.openpgp;

public class PGPSignatureException
    extends PGPException
{
    public PGPSignatureException(String message)
    {
        super(message);
    }

    public PGPSignatureException(String message, Exception cause)
    {
        super(message, cause);
    }
}
