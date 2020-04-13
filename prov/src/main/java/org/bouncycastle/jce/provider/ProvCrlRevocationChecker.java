package org.bouncycastle.jce.provider;

import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.bouncycastle.jcajce.PKIXCertRevocationChecker;
import org.bouncycastle.jcajce.PKIXCertRevocationCheckerParameters;
import org.bouncycastle.jcajce.util.JcaJceHelper;

class ProvCrlRevocationChecker
    implements PKIXCertRevocationChecker
{
    private final JcaJceHelper helper;
    private PKIXCertRevocationCheckerParameters params;

    public ProvCrlRevocationChecker(JcaJceHelper helper)
    {
        this.helper = helper;
    }

    public void setParameter(String name, Object value)
    {

    }

    public void initialize(PKIXCertRevocationCheckerParameters params)
    {
        this.params = params;
    }

    public void init(boolean forForward)
        throws CertPathValidatorException
    {
        if (forForward)
        {
            throw new CertPathValidatorException("forward checking not supported");
        }
    }

    public void check(Certificate certificate)
        throws CertPathValidatorException
    {
        try
        {
            RFC3280CertPathUtilities.checkCRLs(params,
                params.getParamsPKIX(), (X509Certificate)certificate, params.getValidDate(), params.getSigningCert(), params.getWorkingPublicKey(), params.getCertPath().getCertificates(), helper);
        }
        catch (AnnotatedException e)
        {
            Throwable cause = e;
            if (null != e.getCause())
            {
                cause = e.getCause();
            }
            throw new CertPathValidatorException(e.getMessage(), cause, params.getCertPath(), params.getIndex());
        }
    }
}
