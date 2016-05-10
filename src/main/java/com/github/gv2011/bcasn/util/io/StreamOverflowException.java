package com.github.gv2011.bcasn.util.io;

import java.io.IOException;

/**
 * Exception thrown when too much data is written to an InputStream
 */
public class StreamOverflowException
    extends IOException
{
    public StreamOverflowException(String msg)
    {
        super(msg);
    }
}
