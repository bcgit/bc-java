package org.bouncycastle.tls.crypto.impl.jcajce;

/**
 * In earlier JDK's these do not allow nested exceptions
 */
class Exceptions
{
    static IllegalStateException illegalStateException(String message, Throwable cause)
    {
        return new IllegalStateException(message, cause);
    }

    static IllegalArgumentException illegalArgumentException(String message, Throwable cause)
    {
        return new IllegalArgumentException(message, cause);
    }
}
