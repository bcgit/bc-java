package org.bouncycastle.est.jcajce;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRL;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Set;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;


/**
 * General utility methods for building common objects for supporting the JCA/JCE/JSSE.
 */
public class JcaJceUtils
{

    public static X509TrustManager getTrustAllTrustManager()
    {

        //
        // Trust manager signal distrust by throwing exceptions.
        // This one trust all by doing nothing.
        //

        return new X509TrustManager()
        {
            public void checkClientTrusted(java.security.cert.X509Certificate[] x509Certificates, String s)
                throws java.security.cert.CertificateException
            {

            }

            public void checkServerTrusted(java.security.cert.X509Certificate[] x509Certificates, String s)
                throws java.security.cert.CertificateException
            {

            }

            public java.security.cert.X509Certificate[] getAcceptedIssuers()
            {
                return new java.security.cert.X509Certificate[0];
            }
        };

    }

    public static X509TrustManager[] getCertPathTrustManager(final Set<TrustAnchor> anchors, final CRL[] revocationLists)
    {
        final X509Certificate[] x509CertificateTrustAnchors = new X509Certificate[anchors.size()];
        int c = 0;
        for (Iterator it = anchors.iterator(); it.hasNext();)
        {
            TrustAnchor ta = (TrustAnchor)it.next();

            x509CertificateTrustAnchors[c++] = ta.getTrustedCert();
        }

        return new X509TrustManager[]{new X509TrustManager()
        {
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s)
                throws CertificateException
            {

            }

            public void checkServerTrusted(X509Certificate[] x509Certificates, String s)
                throws CertificateException
            {
                try
                {
                    CertStore certStore = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(Arrays.asList(x509Certificates)), "BC");

                    CertPathBuilder pathBuilder = CertPathBuilder.getInstance("PKIX", "BC");

                    X509CertSelector constraints = new X509CertSelector();

                    constraints.setCertificate(x509Certificates[0]);


                    PKIXBuilderParameters param = new PKIXBuilderParameters(anchors, constraints);
                    param.addCertStore(certStore);
                    if (revocationLists != null)
                    {
                        param.setRevocationEnabled(true);
                        param.addCertStore(
                            CertStore.getInstance(
                                "Collection",
                                new CollectionCertStoreParameters(Arrays.asList(revocationLists)
                                )));
                    }
                    else
                    {
                        param.setRevocationEnabled(false);
                    }

                    PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult)pathBuilder.build(param);

                    validateServerCertUsage(x509Certificates[0]);

                }
                catch (CertificateException e)
                {
                    throw e;
                }
                catch (GeneralSecurityException e)
                {
                    throw new CertificateException("unable to process certificates: " + e.getMessage(), e);
                }
            }

            public X509Certificate[] getAcceptedIssuers()
            {
                X509Certificate[] rv = new X509Certificate[x509CertificateTrustAnchors.length];

                System.arraycopy(x509CertificateTrustAnchors, 0, rv, 0, rv.length);

                return rv;
            }
        }
        };
    }

    public static void validateServerCertUsage(X509Certificate x509Certificate)
        throws CertificateException
    {
        try
        {
            X509CertificateHolder cert = new X509CertificateHolder(x509Certificate.getEncoded());

            KeyUsage keyUsage = KeyUsage.fromExtensions(cert.getExtensions());

            if (keyUsage != null)
            {
                if (keyUsage.hasUsages(KeyUsage.keyCertSign))
                {
                    throw new CertificateException("Key usage must not contain keyCertSign");
                }

                if (!(keyUsage.hasUsages(KeyUsage.digitalSignature) || keyUsage.hasUsages(KeyUsage.keyEncipherment)))
                {
                    throw new CertificateException("Key usage must be none, digitalSignature or keyEncipherment");
                }
            }

            //
            // Check extended key usage.
            //
            ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.fromExtensions(cert.getExtensions());

            if (extendedKeyUsage != null)
            {
                if (!(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_serverAuth) ||
                    extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_msSGC) ||
                    extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_nsSGC)))
                {
                    throw new CertificateException("Certificate extended key usage must include serverAuth, msSGC or nsSGC");
                }
            }

        }
        catch (CertificateException c)
        {
            throw c;
        }
        catch (Exception e)
        {
            throw new CertificateException(e.getMessage(), e);
        }
    }


    public static KeyManagerFactory createKeyManagerFactory(
        String type,
        String provider,
        KeyStore clientKeyStore,
        char[] clientKeyStorePass)
        throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException
    {
        KeyManagerFactory keyManagerFactory = null;
        if (type == null && provider == null)
        {
            keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        }
        else if (provider == null)
        {
            keyManagerFactory = KeyManagerFactory.getInstance(type);
        }
        else
        {
            keyManagerFactory = KeyManagerFactory.getInstance(type, provider);
        }
        keyManagerFactory.init(clientKeyStore, clientKeyStorePass);
        return keyManagerFactory;
    }
}
