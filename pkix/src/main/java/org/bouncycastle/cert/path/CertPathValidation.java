package org.bouncycastle.cert.path;

import org.bouncycastle.cert.X509CertificateHolder;

public interface CertPathValidation
{
    public void validate(int index, X509CertificateHolder certificate)
        throws CertPathValidationException;
}
