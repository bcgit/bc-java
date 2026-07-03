package org.bouncycastle.jcajce.provider.util;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public class SecurityExceptions
{
    private SecurityExceptions()
    {

    }

    public static InvalidKeySpecException invalidKeySpecException(String message, Throwable cause)
    {
        // InvalidKeySpecException(String, Throwable) only exists from Java 5; initCause keeps the
        // legacy (Java 4) builds compiling, so do not "simplify" this to the two-arg constructor.
        return (InvalidKeySpecException)new InvalidKeySpecException(message).initCause(cause);
    }

    public static GeneralSecurityException generalSecurityException(String message, Throwable cause)
    {
        return (GeneralSecurityException)new GeneralSecurityException(message).initCause(cause);
    }

    public static InvalidKeyException invalidKeyException(String message, Throwable cause)
    {
        return (InvalidKeyException)new InvalidKeyException(message).initCause(cause);
    }

    public static SignatureException signatureException(String message, Throwable cause)
    {
        return (SignatureException)new SignatureException(message).initCause(cause);
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
