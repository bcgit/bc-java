package org.bouncycastle.jcajce;

import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;

public interface PKIXCertRevocationChecker
{
    void initialize(PKIXCertRevocationCheckerParameters params);

    void check(Certificate cert)
        throws CertPathValidatorException;
}
