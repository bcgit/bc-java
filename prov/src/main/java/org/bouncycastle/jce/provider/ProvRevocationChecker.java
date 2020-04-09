package org.bouncycastle.jce.provider;

import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.PKIXRevocationChecker;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import org.bouncycastle.jcajce.PKIXCertRevocationChecker;
import org.bouncycastle.jcajce.PKIXCertRevocationCheckerParameters;
import org.bouncycastle.jcajce.util.JcaJceHelper;

class ProvRevocationChecker
    extends PKIXRevocationChecker
    implements PKIXCertRevocationChecker
{
    private final ProvCrlRevocationChecker checker;

    public ProvRevocationChecker(JcaJceHelper helper)
    {
        this.checker = new ProvCrlRevocationChecker(helper);
    }

    public void initialize(PKIXCertRevocationCheckerParameters parameters)
    {
        checker.initialize(parameters);
    }

    public List<CertPathValidatorException> getSoftFailExceptions()
    {
        return null;
    }

    public void init(boolean forForward)
        throws CertPathValidatorException
    {
         checker.init(forForward);
    }

    public boolean isForwardCheckingSupported()
    {
        return false;
    }

    public Set<String> getSupportedExtensions()
    {
        return null;
    }

    public void check(Certificate certificate, Collection<String> collection)
        throws CertPathValidatorException
    {
        checker.check(certificate);
    }

    public void check(Certificate certificate)
        throws CertPathValidatorException
    {
         checker.check(certificate);
    }
}
