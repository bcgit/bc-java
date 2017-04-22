package org.bouncycastle.jsse.provider;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Provider;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Set;

import javax.net.ssl.X509TrustManager;

class ProvX509TrustManager
    implements X509TrustManager
{
    private final Provider pkixProvider;
    private final Set trustAnchors;
    private final PKIXParameters baseParameters;

    public ProvX509TrustManager(Provider pkixProvider, Set trustAnchors)
        throws InvalidAlgorithmParameterException
    {
        this.pkixProvider = pkixProvider;
        this.trustAnchors = trustAnchors;
        this.baseParameters = new PKIXBuilderParameters(trustAnchors, new X509CertSelector());
        this.baseParameters.setRevocationEnabled(false);
    }

    public ProvX509TrustManager(Provider pkixProvider, PKIXParameters baseParameters)
        throws InvalidAlgorithmParameterException
    {
        this.pkixProvider = pkixProvider;
        this.trustAnchors = baseParameters.getTrustAnchors();
        if (baseParameters instanceof PKIXBuilderParameters)
        {
            this.baseParameters = baseParameters;
        }
        else
        {
            this.baseParameters = new PKIXBuilderParameters(baseParameters.getTrustAnchors(), baseParameters.getTargetCertConstraints());
            this.baseParameters.setCertStores(baseParameters.getCertStores());
            this.baseParameters.setRevocationEnabled(baseParameters.isRevocationEnabled());
            this.baseParameters.setCertPathCheckers(baseParameters.getCertPathCheckers());
            this.baseParameters.setDate(baseParameters.getDate());
            this.baseParameters.setAnyPolicyInhibited(baseParameters.isAnyPolicyInhibited());
            this.baseParameters.setPolicyMappingInhibited(baseParameters.isPolicyMappingInhibited());
            this.baseParameters.setExplicitPolicyRequired(baseParameters.isExplicitPolicyRequired());
        }
    }

    public void checkClientTrusted(X509Certificate[] x509Certificates, String authType)
        throws CertificateException
    {
        // TODO: need to confirm cert and client identity match
        // TODO: need to make sure authType makes sense.
        validatePath(x509Certificates);
    }

    public void checkServerTrusted(X509Certificate[] x509Certificates, String authType)
        throws CertificateException
    {

        // TODO: need to confirm cert and server identity match
        // TODO: need to make sure authType makes sense.
        validatePath(x509Certificates);
    }

    public X509Certificate[] getAcceptedIssuers()
    {
        try
        {
            X509Certificate[] certs = new X509Certificate[trustAnchors.size()];
            int count = 0;

            for (Iterator it = trustAnchors.iterator(); it.hasNext();)
            {
                certs[count++] = ((TrustAnchor)it.next()).getTrustedCert();
            }

            return certs;
        }
        catch (Exception e)
        {
            return new X509Certificate[0];
        }
    }

    protected void validatePath(X509Certificate[] x509Certificates)
        throws CertificateException
    {
        try
        {
            CertStore certStore = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(Arrays.asList(x509Certificates)), pkixProvider);

            CertPathBuilder pathBuilder = CertPathBuilder.getInstance("PKIX", pkixProvider);

            X509CertSelector constraints = (X509CertSelector)baseParameters.getTargetCertConstraints().clone();

            constraints.setCertificate(x509Certificates[0]);

            PKIXBuilderParameters param = (PKIXBuilderParameters)baseParameters.clone();

            param.addCertStore(certStore);
            param.setTargetCertConstraints(constraints);

            PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult)pathBuilder.build(param);
        }
        catch (GeneralSecurityException e)
        {
            throw new CertificateException("unable to process certificates: " + e.getMessage(), e);
        }
    }
}
