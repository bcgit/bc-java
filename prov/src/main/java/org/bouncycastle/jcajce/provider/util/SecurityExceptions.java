package org.bouncycastle.jcajce.provider.util;

import java.security.UnrecoverableKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public class SecurityExceptions
{
    private SecurityExceptions()
    {

    }

    public static UnrecoverableKeyException unrecoverableKeyException(String message, Throwable cause)
    {
        return (UnrecoverableKeyException)new UnrecoverableKeyException(message).initCause(cause);
    }

    public static IllegalBlockSizeException illegalBlockSizeException(String message, Throwable cause)
    {
        return (IllegalBlockSizeException)new IllegalBlockSizeException(message).initCause(cause);
    }

    public static BadPaddingException badPaddingException(String message, Throwable cause)
    {
        return (BadPaddingException)new BadPaddingException(message).initCause(cause);
    }
}
