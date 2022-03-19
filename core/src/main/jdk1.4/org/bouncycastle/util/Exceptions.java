package org.bouncycastle.util;

public class Exceptions
{
    public static IllegalArgumentException illegalArgumentException(String message, final Throwable cause)
    {
        return new IllegalArgumentException(message)
        {
            public Throwable getCause()
            {
                return cause;
            }
        };
    }

    public static IllegalStateException illegalStateException(String message, final Throwable cause)
    {
        return new IllegalStateException(message)
        {
            public Throwable getCause()
            {
                return cause;
            }
        };
    }
}
