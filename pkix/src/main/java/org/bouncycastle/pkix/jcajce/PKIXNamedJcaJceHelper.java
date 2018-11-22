package org.bouncycastle.pkix.jcajce;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertPathBuilder;

import org.bouncycastle.jcajce.util.NamedJcaJceHelper;

class PKIXNamedJcaJceHelper
    extends NamedJcaJceHelper
    implements PKIXJcaJceHelper
{
    public PKIXNamedJcaJceHelper(String providerName)
    {
        super(providerName);
    }

    public CertPathBuilder createCertPathBuilder(String type)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        return CertPathBuilder.getInstance(type, providerName);
    }
}
