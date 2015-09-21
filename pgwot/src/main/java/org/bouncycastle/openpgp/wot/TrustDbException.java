package org.bouncycastle.openpgp.wot;

/**
 * Exception thrown by {@link TrustDbImpl} and related classes.
 *
 * @author Marco หงุ่ยตระกูล-Schulze - marco at codewizards dot co
 */
public class TrustDbException extends RuntimeException
{
    private static final long serialVersionUID = 1L;

    public TrustDbException()
    {
    }

    public TrustDbException(String message)
    {
        super(message);
    }

    public TrustDbException(Throwable cause)
    {
        super(cause);
    }

    public TrustDbException(String message, Throwable cause)
    {
        super(message, cause);
    }
}
