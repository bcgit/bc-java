package org.bouncycastle.util;

import java.io.IOException;

public class Exceptions
{
    // initCause() (since Java 1.4) is used in preference to the (String, Throwable) constructors
    // so this single class works on every JDK the legacy builds target - IllegalArgumentException
    // and IllegalStateException only gained that constructor in Java 5, and IOException in Java 6.
    // Do not "simplify" these to the two-arg constructors; it would break the Java 4 build.

    public static IllegalArgumentException illegalArgumentException(String message, Throwable cause)
    {
        return (IllegalArgumentException)new IllegalArgumentException(message).initCause(cause);
    }

    public static IllegalStateException illegalStateException(String message, Throwable cause)
    {
        return (IllegalStateException)new IllegalStateException(message).initCause(cause);
    }

    public static IOException ioException(String message, Throwable cause)
    {
        return (IOException)new IOException(message).initCause(cause);
    }

}
