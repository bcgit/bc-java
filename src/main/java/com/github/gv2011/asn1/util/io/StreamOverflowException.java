package com.github.gv2011.asn1.util.io;

/**
 * Exception thrown when too much data is written to an InputStream
 */
public class StreamOverflowException extends RuntimeException
{
  private static final long serialVersionUID = -6619517775101896395L;

    public StreamOverflowException(final String msg)
    {
        super(msg);
    }
}
