package org.bouncycastle.jsse.provider;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.cert.CertPathParameters;
import java.security.cert.Certificate;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;

class ProvTrustManagerFactorySpi
    extends TrustManagerFactorySpi
{
    private static Logger LOG = Logger.getLogger(ProvTrustManagerFactorySpi.class.getName());

    static final String CACERTS_PATH;
    static final String JSSECACERTS_PATH;

    static
    {
        String javaHome = PropertyUtils.getSystemProperty("java.home");
        CACERTS_PATH = javaHome + "/lib/security/cacerts".replace('/', File.separatorChar);
        JSSECACERTS_PATH = javaHome + "/lib/security/jssecacerts".replace('/', File.separatorChar);
    }

    protected final Provider pkixProvider;

    protected ProvX509TrustManager x509TrustManager;

    public ProvTrustManagerFactorySpi(Provider pkixProvider)
    {
        this.pkixProvider = pkixProvider;
    }

    protected TrustManager[] engineGetTrustManagers()
    {
        return new TrustManager[]{ x509TrustManager.getExportedX509TrustManager() };
    }

    protected void engineInit(KeyStore ks)
        throws KeyStoreException
    {
        try
        {
            if (ks == null)
            {
                String defaultType = KeyStore.getDefaultType();

                String tsPath = null;
                char[] tsPassword = null;

                String tsPathProp = PropertyUtils.getSystemProperty("javax.net.ssl.trustStore");
                if (tsPathProp != null)
                {
                    if (new File(tsPathProp).exists())
                    {
                        tsPath = tsPathProp;

                        String tsPasswordProp = PropertyUtils.getSystemProperty("javax.net.ssl.trustStorePassword");
                        if (tsPasswordProp != null)
                        {
                            tsPassword = tsPasswordProp.toCharArray();
                        }
                    }
                }
                else if (new File(JSSECACERTS_PATH).exists())
                {
                    defaultType = "jks";
                    tsPath = JSSECACERTS_PATH;
                }
                else if (new File(CACERTS_PATH).exists())
                {
                    defaultType = "jks";
                    tsPath = CACERTS_PATH;
                }

                ks = createTrustStore(defaultType);

                if (tsPath == null)
                {
                    ks.load(null, null);
                    LOG.warning("Initialized with empty trust store");
                }
                else
                {
                    InputStream tsInput = new BufferedInputStream(new FileInputStream(tsPath));
                    ks.load(tsInput, tsPassword);
                    tsInput.close();
                    LOG.info("Initialized with trust store at path: " + tsPath);
                }
            }

            Set<TrustAnchor> trustAnchors = getTrustAnchors(ks);

            this.x509TrustManager = new ProvX509TrustManager(pkixProvider, trustAnchors);
        }
        catch (Exception e)
        {
            throw new KeyStoreException("initialization failed", e);
        }
    }

    protected void engineInit(ManagerFactoryParameters spec)
        throws InvalidAlgorithmParameterException
    {
        if (spec instanceof CertPathTrustManagerParameters)
        {
            try
            {
                CertPathParameters param = ((CertPathTrustManagerParameters)spec).getParameters();

                if (!(param instanceof PKIXParameters))
                {
                    throw new InvalidAlgorithmParameterException("parameters must inherit from PKIXParameters");
                }

                PKIXParameters pkixParam = (PKIXParameters)param;

                this.x509TrustManager = new ProvX509TrustManager(pkixProvider, pkixParam);
            }
            catch (GeneralSecurityException e)
            {
                throw new InvalidAlgorithmParameterException("unable to process parameters: " + e.getMessage(), e);
            }
        }
        else
        {
            if (spec == null)
            {
                throw new InvalidAlgorithmParameterException("spec cannot be null");
            }
            throw new InvalidAlgorithmParameterException("unknown spec: " + spec.getClass().getName());
        }
    }

    private String getTrustStoreType(String defaultType)
    {
        String tsType = PropertyUtils.getSystemProperty("javax.net.ssl.trustStoreType");
        if (tsType == null)
        {
            tsType = defaultType;
        }

        return tsType;
    }

    private KeyStore createTrustStore(String defaultType)
        throws NoSuchProviderException, KeyStoreException
    {
        String tsType = getTrustStoreType(defaultType);
        String tsProv = PropertyUtils.getSystemProperty("javax.net.ssl.trustStoreProvider");
        KeyStore ts = (tsProv == null || tsProv.length() < 1)
            ?   KeyStore.getInstance(tsType)
            :   KeyStore.getInstance(tsType, tsProv);

        return ts;
    }

    private Set<TrustAnchor> getTrustAnchors(KeyStore trustStore)
        throws KeyStoreException
    {
        Set<TrustAnchor> anchors = new HashSet<TrustAnchor>(trustStore.size());
        for (Enumeration<String> en = trustStore.aliases(); en.hasMoreElements();)
        {
            String alias = (String)en.nextElement();
            if (trustStore.isCertificateEntry(alias))
            {
                Certificate cert = trustStore.getCertificate(alias);
                if (cert instanceof X509Certificate)
                {
                    anchors.add(new TrustAnchor((X509Certificate)cert, null));
                }
            }
        }

        return anchors;
    }
}
