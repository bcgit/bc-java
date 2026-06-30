package org.bouncycastle.pkcs;

/**
 * General checked exception thrown by classes in {@link org.bouncycastle.pkcs} and its
 * sub-packages.
 */
public class PKCSException
    extends Exception
{
    private Throwable cause;

    public PKCSException(String msg, Throwable cause)
    {
        super(msg);

        this.cause = cause;
    }

    public PKCSException(String msg)
    {
        super(msg);
    }

    public Throwable getCause()
    {
        return cause;
    }
}
