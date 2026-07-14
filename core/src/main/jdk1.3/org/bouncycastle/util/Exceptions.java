package org.bouncycastle.util;

import java.io.IOException;

// NOTE: jdk1.3 overlay. Throwable.initCause() is a Java 1.4 API and does not exist on JDK 1.3,
// so the base class (which chains via initCause) will not compile here. JDK 1.3 has no
// Throwable.getCause() either, so no 1.3 caller can observe a chained cause: we drop the cause
// and keep the message text verbatim (it is asserted on elsewhere). Keep every signature in
// lockstep with the base Exceptions so callers compile unchanged.
public class Exceptions
{
    public static IllegalArgumentException illegalArgumentException(String message, Throwable cause)
    {
        return new IllegalArgumentException(message);
    }

    public static IllegalStateException illegalStateException(String message, Throwable cause)
    {
        return new IllegalStateException(message);
    }

    public static IOException ioException(String message, Throwable cause)
    {
        return new IOException(message);
    }

}
