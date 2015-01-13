package org.bouncycastle.jcajce;

import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.util.Collection;

import org.bouncycastle.util.Selector;

/**
 * This class is a Selector implementation for certificates.
 * 
 * @see org.bouncycastle.util.Selector
 */
public class PKIXCertStoreSelector<T extends Certificate>
    implements Selector<T>
{
    public static class Builder
    {
        private final CertSelector baseSelector;

        public Builder(CertSelector certSelector)
        {
            this.baseSelector = (CertSelector)certSelector.clone();
        }

        public PKIXCertStoreSelector<? extends Certificate> build()
        {
            return new PKIXCertStoreSelector(baseSelector);
        }
    }

    private final CertSelector baseSelector;

    private PKIXCertStoreSelector(CertSelector baseSelector)
    {
        this.baseSelector = baseSelector;
    }

    public boolean match(Certificate cert)
    {
        return baseSelector.match(cert);
    }

    public Object clone()
    {
        return new PKIXCertStoreSelector(baseSelector);
    }

    public static Collection<? extends Certificate> getCertificates(final PKIXCertStoreSelector selector, CertStore certStore)
        throws CertStoreException
    {
        return certStore.getCertificates(new CertSelector()
        {
            public boolean match(Certificate certificate)
            {
                return (selector == null) ? true : selector.match(certificate);
            }

            public Object clone()
            {
                return this;
            }
        });
    }
}
