package org.bouncycastle.util;

public class Exceptions
{
    public static IllegalArgumentException illegalArgumentException(String message, Throwable cause)
    {
        return new IllegalArgumentException(message, cause);
    }

    public static IllegalStateException illegalStateException(String message, Throwable cause)
    {
        return new IllegalStateException(message, cause);
    }
}
