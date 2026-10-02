package org.bouncycastle.util;

import java.io.IOException;
import java.io.InvalidObjectException;

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

    // InvalidObjectException has no (String, Throwable) constructor in any Java version.
    public static InvalidObjectException invalidObjectException(String message, Throwable cause)
    {
        return (InvalidObjectException)new InvalidObjectException(message).initCause(cause);
    }

}
