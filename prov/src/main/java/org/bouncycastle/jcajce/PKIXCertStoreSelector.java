package org.bouncycastle.jcajce;

import java.io.IOException;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509CertSelector;
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
    /**
     * Builder for a PKIXCertStoreSelector.
     */
    public static class Builder
    {
        private final CertSelector baseSelector;

        /**
         * Constructor initializing a builder with a CertSelector.
         *
         * @param certSelector the CertSelector to copy the match details from.
         */
        public Builder(CertSelector certSelector)
        {
            this.baseSelector = (CertSelector)certSelector.clone();
        }

        /**
         * Build a selector.
         *
         * @return a new PKIXCertStoreSelector
         */
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
        return certStore.getCertificates(new SelectorClone(selector));
    }

    private static class SelectorClone
        extends X509CertSelector
    {
        private final PKIXCertStoreSelector selector;

        SelectorClone(PKIXCertStoreSelector selector)
        {
            this.selector = selector;

            if (selector.baseSelector instanceof X509CertSelector)
            {
                X509CertSelector baseSelector = (X509CertSelector)selector.baseSelector;

                this.setAuthorityKeyIdentifier(baseSelector.getAuthorityKeyIdentifier());
                this.setBasicConstraints(baseSelector.getBasicConstraints());
                this.setCertificate(baseSelector.getCertificate());
                this.setCertificateValid(baseSelector.getCertificateValid());
                this.setKeyUsage(baseSelector.getKeyUsage());
                this.setMatchAllSubjectAltNames(baseSelector.getMatchAllSubjectAltNames());
                this.setPrivateKeyValid(baseSelector.getPrivateKeyValid());
                this.setSerialNumber(baseSelector.getSerialNumber());
                this.setSubjectKeyIdentifier(baseSelector.getSubjectKeyIdentifier());
                this.setSubjectPublicKey(baseSelector.getSubjectPublicKey());

                try
                {
                    this.setExtendedKeyUsage(baseSelector.getExtendedKeyUsage());
                    this.setIssuer(baseSelector.getIssuerAsBytes());
                    this.setNameConstraints(baseSelector.getNameConstraints());
                    this.setPathToNames(baseSelector.getPathToNames());
                    this.setPolicy(baseSelector.getPolicy());
                    this.setSubject(baseSelector.getSubjectAsBytes());
                    this.setSubjectAlternativeNames(baseSelector.getSubjectAlternativeNames());
                    this.setSubjectPublicKeyAlgID(baseSelector.getSubjectPublicKeyAlgID());
                }
                catch (IOException e)
                {
                    throw new IllegalStateException("base selector invalid: " + e.getMessage(), e);
                }
            }
        }

        public boolean match(Certificate certificate)
        {
            return (selector == null) ? (certificate != null) : selector.match(certificate);
        }
    }
}
