package com.github.gv2011.asn1.util.encoders;

/**
 * Exception thrown if an attempt is made to decode invalid data, or some other failure occurs.
 */
public class DecoderException
    extends IllegalStateException
{
    /**
   *
   */
  private static final long serialVersionUID = 972969736256420978L;
    private final Throwable cause;

    DecoderException(final String msg, final Throwable cause)
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
