package org.bouncycastle.mime;

import java.io.IOException;

/**
 * General IOException thrown in the mime package and its sub-packages.
 */
public class MimeIOException
    extends IOException
{
    private Throwable cause;

    public MimeIOException(String msg, Throwable cause)
    {
        super(msg);

        this.cause = cause;
    }

    public MimeIOException(String msg)
    {
        super(msg);
    }

    public Throwable getCause()
    {
        return cause;
    }
}
