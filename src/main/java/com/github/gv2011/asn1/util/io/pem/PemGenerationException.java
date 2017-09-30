package com.github.gv2011.asn1.util.io.pem;

/**
 * Exception thrown on failure to generate a PEM object.
 */
public class PemGenerationException
    extends RuntimeException
{
    private static final long serialVersionUID = 944567446108554789L;

    private Throwable cause;

    public PemGenerationException(final String message, final Throwable cause)
    {
        super(message);
        this.cause = cause;
    }

    public PemGenerationException(final String message)
    {
        super(message);
    }

    @Override
    public Throwable getCause()
    {
        return cause;
    }
}
