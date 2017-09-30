package com.github.gv2011.asn1.util.encoders;

/**
 * Exception thrown if an attempt is made to encode invalid data, or some other failure occurs.
 */
public class EncoderException
    extends IllegalStateException
{
    private static final long serialVersionUID = -3643553776450726733L;

    private final Throwable cause;

    EncoderException(final String msg, final Throwable cause)
    {
        super(msg);

        this.cause = cause;
    }

    @Override
    public Throwable getCause()
    {
        return cause;
    }
}
