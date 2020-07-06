package org.bouncycastle.jcajce;

import java.security.cert.CertSelector;
import java.security.cert.X509CertSelector;
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
public class PKIXCertStoreSelector
    implements Selector
{
    public static class Builder
    {
        private CertSelector baseSelector;

        public Builder(CertSelector certSelector)
        {
            this.baseSelector = (CertSelector)certSelector.clone();
        }

        public PKIXCertStoreSelector build()
        {
            return new PKIXCertStoreSelector(baseSelector);
        }
    }

    private CertSelector baseSelector;

    private PKIXCertStoreSelector(CertSelector baseSelector)
    {
        this.baseSelector = baseSelector;
    }

    /**
     * Return the specific certificate this selector is designed to match.
     * 
     * @return a specific certificate where the selector has been configured explicitly.
     */
    public Certificate getCertificate()
    {
         if (baseSelector instanceof X509CertSelector)
         {
             return ((X509CertSelector)baseSelector).getCertificate();
         }
    
         return null;
    }
    
    public boolean match(Object cert)
    {
        return baseSelector.match((Certificate)cert);
    }

    public Object clone()
    {
        return new PKIXCertStoreSelector(baseSelector);
    }

    public static Collection getCertificates(final PKIXCertStoreSelector selector, CertStore certStore)
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
