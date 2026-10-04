package org.bouncycastle.jce.provider;

/**
 * An AnnotatedException reporting that the certificate under check has been revoked, so the
 * code wrapping it can report java.security.cert.CertPathValidatorException.BasicReason.REVOKED.
 * <p>
 * BasicReason only exists from Java 7, so it is applied by the Java 8 only ProvRevocationChecker
 * rather than here, keeping the CRL path compiling for the legacy builds.
 * </p>
 */
class AnnotatedRevocationException
    extends AnnotatedException
{
    AnnotatedRevocationException(String string)
    {
        super(string);
    }
}
