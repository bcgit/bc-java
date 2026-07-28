package org.bouncycastle.jcajce.provider.util;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import org.bouncycastle.jce.cert.CertPathBuilderException;
import org.bouncycastle.jce.cert.CertPathValidatorException;

// NOTE: jdk1.3 overlay. Throwable.initCause() is a Java 1.4 API absent on JDK 1.3, so the base
// class (which chains via initCause) will not compile here. JDK 1.3 has no Throwable.getCause()
// either, so no 1.3 caller can observe a chained cause: we drop the cause and keep the message
// text verbatim. Keep every factory signature in lockstep with the base SecurityExceptions.
// CertPathValidatorException/CertPathBuilderException are part of the java.security.cert CertPath
// API added in Java 1.4, absent on 1.3 -- the jdk1.3 build's own preprocessor does not auto-rewrite
// these two class names (see docs/jdk13-certpath-overlay-sync-plan.md), so this overlay routes them
// through the org.bouncycastle.jce.cert backport instead. Unlike the JDK-native exceptions above,
// the org.bouncycastle.jce.cert backport exceptions carry their own cause field rather than relying
// on Throwable.initCause()/getCause(), so their two-arg (message, cause) constructor works on 1.3
// and the cause is passed through rather than dropped. CertificateEncodingException predates Java
// 1.4 (it is in java.security.cert since JDK 1.1), so it is left unchanged.
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

    public static NoSuchAlgorithmException noSuchAlgorithmException(String message, Throwable cause)
    {
        return new NoSuchAlgorithmException(message);
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

    public static CertPathValidatorException certPathValidatorException(String message, Throwable cause)
    {
        return new CertPathValidatorException(message, cause);
    }

    public static CertPathBuilderException certPathBuilderException(String message, Throwable cause)
    {
        return new CertPathBuilderException(message, cause);
    }

    public static CertificateEncodingException certificateEncodingException(String message, Throwable cause)
    {
        return new CertificateEncodingException(message);
    }
}
