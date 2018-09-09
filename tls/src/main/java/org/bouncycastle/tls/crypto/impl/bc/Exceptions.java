package org.bouncycastle.tls.crypto.impl.bc;

/**
 * In earlier JDK's these do not allow nested exceptions
 */
class Exceptions
{
    static IllegalArgumentException illegalArgumentException(String message, Throwable cause)
    {
        return new IllegalArgumentException(message, cause);
    }
}
