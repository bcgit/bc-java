package org.bouncycastle.jcajce;

import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;

public interface PKIXCertRevocationChecker
{
    void setParameter(String name, Object value);

    void initialize(PKIXCertRevocationCheckerParameters params)
        throws CertPathValidatorException;

    void check(Certificate cert)
        throws CertPathValidatorException;
}
