package org.bouncycastle.jcajce.provider.util;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

// NOTE: jdk1.3 overlay. Throwable.initCause() is a Java 1.4 API absent on JDK 1.3, so the base
// class (which chains via initCause) will not compile here. JDK 1.3 has no Throwable.getCause()
// either, so no 1.3 caller can observe a chained cause: we drop the cause and keep the message
// text verbatim. Keep every factory signature in lockstep with the base SecurityExceptions.
public class SecurityExceptions
{
    private SecurityExceptions()
    {

    }

    public static InvalidKeySpecException invalidKeySpecException(String message, Throwable cause)
    {
        return new InvalidKeySpecException(message);
    }

    public static GeneralSecurityException generalSecurityException(String message, Throwable cause)
    {
        return new GeneralSecurityException(message);
    }

    public static InvalidKeyException invalidKeyException(String message, Throwable cause)
    {
        return new InvalidKeyException(message);
    }

    public static SignatureException signatureException(String message, Throwable cause)
    {
        return new SignatureException(message);
    }

    public static UnrecoverableKeyException unrecoverableKeyException(String message, Throwable cause)
    {
        return new UnrecoverableKeyException(message);
    }

    public static IllegalBlockSizeException illegalBlockSizeException(String message, Throwable cause)
    {
        return new IllegalBlockSizeException(message);
    }

    public static BadPaddingException badPaddingException(String message, Throwable cause)
    {
        return new BadPaddingException(message);
    }
}
