package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Exception thrown in cases of corrupted or unexpected data in a stream.
 */
public class ASN1Exception
    extends IOException
{
    private Throwable cause;

    /**
     * Base constructor
     *
     * @param message a message concerning the exception.
     */
    ASN1Exception(String message)
    {
        super(message);
    }

    /**
     * Constructor when this exception is due to another one.
     *
     * @param message a message concerning the exception.
     * @param cause the exception that caused this exception to be thrown.
     */
    ASN1Exception(String message, Throwable cause)
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
