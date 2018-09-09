package org.bouncycastle.tls.crypto.impl.bc;

class Exceptions
{
    static IllegalArgumentException illegalArgumentException(String message, Throwable cause)
    {
        return new org.bouncycastle.tls.exception.IllegalArgumentException(message, cause);
    }
}
