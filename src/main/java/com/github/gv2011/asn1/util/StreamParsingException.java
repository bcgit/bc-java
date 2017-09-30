package com.github.gv2011.asn1.util;

public class StreamParsingException
    extends Exception
{
    private static final long serialVersionUID = -5485989784169775835L;

    Throwable _e;

    public StreamParsingException(final String message, final Throwable e)
    {
        super(message);
        _e = e;
    }

    @Override
    public Throwable getCause()
    {
        return _e;
    }
}
