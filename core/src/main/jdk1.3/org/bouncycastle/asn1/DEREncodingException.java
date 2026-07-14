package org.bouncycastle.asn1;

// NOTE: jdk1.3 overlay. Throwable.initCause() is a Java 1.4 API absent on JDK 1.3, so the base
// class's (String, Throwable) constructor (which calls initCause) will not compile here. JDK 1.3
// has no Throwable.getCause() either, so no 1.3 caller can observe the dropped cause: the two-arg
// constructor keeps the message verbatim and discards the cause. Keep both signatures in lockstep
// with the base DEREncodingException so callers compile unchanged.
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
        super(message);
    }
}
