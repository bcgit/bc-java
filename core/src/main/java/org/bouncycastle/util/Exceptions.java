package org.bouncycastle.util;

import java.io.IOException;

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

    public static IOException ioException(String message, Throwable cause)
    {
        return new IOException(message, cause);
    }

}
