package org.bouncycastle.openpgp;

/**
 * generic exception class for PGP encoding/decoding problems
 */
public class PGPException 
    extends Exception 
{
    Exception    underlying;
    
    public PGPException(
        String    message)
    {
        super(message);
    }
    
    public PGPException(
        String        message,
        Exception    underlying)
    {
        super(message);
        this.underlying = underlying;
    }
    
    public Exception getUnderlyingException()
    {
        return underlying;
    }
    
    
    public Throwable getCause()
    {
        return underlying;
    }
}
