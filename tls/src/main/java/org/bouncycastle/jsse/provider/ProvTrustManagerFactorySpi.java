package org.bouncycastle.jsse.provider;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.cert.CertPathParameters;
import java.security.cert.Certificate;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;

import org.bouncycastle.jcajce.util.JcaJceHelper;

class ProvTrustManagerFactorySpi
    extends TrustManagerFactorySpi
{
    private static final Logger LOG = Logger.getLogger(ProvTrustManagerFactorySpi.class.getName());

    static KeyStore getDefaultTrustStore() throws Exception
    {
        String defaultType = KeyStore.getDefaultType();

        String tsPath = null;
        char[] tsPassword = null;

        String tsPathProp = PropertyUtils.getSystemProperty("javax.net.ssl.trustStore");
        if ("NONE".equals(tsPathProp))
        {
            // Do not try to load any file
        }
        else if (null != tsPathProp)
        {
            if (new File(tsPathProp).exists())
            {
                tsPath = tsPathProp;
            }
        }
        else
        {
            String javaHome = PropertyUtils.getSystemProperty("java.home");
            if (null != javaHome)
            {
                String jsseCacertsPath = javaHome + "/lib/security/jssecacerts".replace("/", File.separator);
                if (new File(jsseCacertsPath).exists())
                {
                    defaultType = "jks";
                    tsPath = jsseCacertsPath;
                }
                else
                {
                    String cacertsPath = javaHome + "/lib/security/cacerts".replace("/", File.separator);
                    if (new File(cacertsPath).exists())
                    {
                        defaultType = "jks";
                        tsPath = cacertsPath;
                    }
                }
            }
        }

        KeyStore ks = createTrustStore(defaultType);

        String tsPasswordProp = PropertyUtils.getSystemProperty("javax.net.ssl.trustStorePassword");
        if (null != tsPasswordProp)
        {
            tsPassword = tsPasswordProp.toCharArray();
        }

        InputStream tsInput = null;
        try
        {
            if (null == tsPath)
            {
                LOG.info("Initializing empty trust store");
            }
            else
            {
                LOG.info("Initializing with trust store at path: " + tsPath);
                tsInput = new BufferedInputStream(new FileInputStream(tsPath));
            }

            ks.load(tsInput, tsPassword);
        }
        finally
        {
            if (null != tsInput)
            {
                tsInput.close();
            }
        }

        return ks;
    }

    protected final JcaJceHelper helper;

    protected ProvX509TrustManager x509TrustManager;

    ProvTrustManagerFactorySpi(JcaJceHelper helper)
    {
        this.helper = helper;
    }

    @Override
    protected TrustManager[] engineGetTrustManagers()
    {
        if (null == x509TrustManager)
        {
            throw new IllegalStateException("TrustManagerFactory not initialized");
        }

        return new TrustManager[]{ x509TrustManager.getExportX509TrustManager() };
    }

    @Override
    protected void engineInit(KeyStore ks)
        throws KeyStoreException
    {
        if (null == ks)
        {
            try
            {
                ks = getDefaultTrustStore();
            }
            catch (SecurityException e)
            {
                LOG.log(Level.WARNING, "Skipped default trust store", e);
                // Ignore
            }
            catch (Error e)
            {
                LOG.log(Level.WARNING, "Skipped default trust store", e);
                throw e;
            }
            catch (RuntimeException e)
            {
                LOG.log(Level.WARNING, "Skipped default trust store", e);
                throw e;
            }
            catch (Exception e)
            {
                LOG.log(Level.WARNING, "Skipped default trust store", e);
                throw new KeyStoreException("Failed to load default trust store", e);
            }
        }

        Set<TrustAnchor> trustAnchors = getTrustAnchors(ks);

        try
        {
            this.x509TrustManager = new ProvX509TrustManager(helper, trustAnchors);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new KeyStoreException("Failed to create trust manager", e);
        }
    }

    @Override
    protected void engineInit(ManagerFactoryParameters spec)
        throws InvalidAlgorithmParameterException
    {
        if (spec instanceof CertPathTrustManagerParameters)
        {
            CertPathParameters certPathParameters = ((CertPathTrustManagerParameters)spec).getParameters();
            if (!(certPathParameters instanceof PKIXParameters))
            {
                throw new InvalidAlgorithmParameterException("parameters must inherit from PKIXParameters");
            }

            this.x509TrustManager = new ProvX509TrustManager(helper, (PKIXParameters)certPathParameters);
        }
        else if (null == spec)
        {
            throw new InvalidAlgorithmParameterException("spec cannot be null");
        }
        else
        {
            throw new InvalidAlgorithmParameterException("unknown spec: " + spec.getClass().getName());
        }
    }

    private static KeyStore createTrustStore(String defaultType)
        throws NoSuchProviderException, KeyStoreException
    {
        String tsType = getTrustStoreType(defaultType);
        String tsProv = PropertyUtils.getSystemProperty("javax.net.ssl.trustStoreProvider");
        return (null == tsProv || tsProv.length() < 1)
            ?   KeyStore.getInstance(tsType)
            :   KeyStore.getInstance(tsType, tsProv);
    }

    private static Set<TrustAnchor> getTrustAnchors(KeyStore trustStore)
        throws KeyStoreException
    {
        if (null == trustStore)
        {
            return Collections.emptySet();
        }

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

    private static String getTrustStoreType(String defaultType)
    {
        String tsType = PropertyUtils.getSystemProperty("javax.net.ssl.trustStoreType");
        return (null == tsType) ? defaultType : tsType;
    }
}
