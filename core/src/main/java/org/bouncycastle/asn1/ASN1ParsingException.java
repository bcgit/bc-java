package org.bouncycastle.asn1;

/**
 * Exception thrown when correctly encoded, but unexpected data is found in a stream while building an object.
 */
public class ASN1ParsingException
    extends IllegalStateException
{
    private Throwable cause;

    /**
     * Base constructor
     *
     * @param message a message concerning the exception.
     */
    public ASN1ParsingException(String message)
    {
        super(message);
    }

    /**
     * Constructor when this exception is due to another one.
     *
     * @param message a message concerning the exception.
     * @param cause the exception that caused this exception to be thrown.
     */
    public ASN1ParsingException(String message, Throwable cause)
    {
        super(message);
        this.cause = cause;
    }

    /**
     * Return the underlying cause of this exception, if any.
     *
     * @return the exception causing this one, null if there isn't one.
     */
    public Throwable getCause()
    {
        return cause;
    }
}
