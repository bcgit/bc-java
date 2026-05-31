package org.bouncycastle.asn1;

/**
 * Exception thrown when an ASN.1 primitive cannot be serialized as DER - typically because
 * its in-memory contents do not satisfy the DER restrictions of X.690 (e.g. a UTCTime /
 * GeneralizedTime parsed leniently from the wire that is then asked to round-trip through a
 * {@code DEROutputStream}).
 */
public class DEREncodingException
    extends IllegalStateException
{
    /**
     * Base constructor.
     *
     * @param message a message concerning the exception.
     */
    public DEREncodingException(String message)
    {
        super(message);
    }

    /**
     * Constructor when this exception is due to another one.
     *
     * @param message a message concerning the exception.
     * @param cause the exception that caused this exception to be thrown.
     */
    public DEREncodingException(String message, Throwable cause)
    {
        super(message, cause);
    }
}
