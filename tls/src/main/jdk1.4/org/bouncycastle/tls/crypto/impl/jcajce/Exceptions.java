package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;

class Exceptions
{
    static IllegalStateException illegalStateException(String message, Throwable cause)
    {
        return new org.bouncycastle.tls.exception.IllegalStateException(message, cause);
    }

    static IllegalArgumentException illegalArgumentException(String message, Throwable cause)
    {
        return new org.bouncycastle.tls.exception.IllegalArgumentException(message, cause);
    }

    static IOException ioException(String message, Throwable cause)
    {
        return new org.bouncycastle.tls.exception.IOException(message, cause);
    }
}
