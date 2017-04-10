package org.bouncycastle.jsse.provider;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;
import javax.net.ssl.X509TrustManager;

class ProvTrustManagerFactorySpi
    extends TrustManagerFactorySpi
{
    static final boolean hasExtendedTrustManager;
    static final String CACERTS_PATH;
    static final String JSSECACERTS_PATH;

    static
    {
        Class<?> clazz = null;
        try
        {
            clazz = ProvSSLServerSocket.class.getClassLoader().loadClass("javax.net.ssl.X509ExtendedTrustManager");
        }
        catch (Exception e)
        {
            clazz = null;
        }

        hasExtendedTrustManager = (clazz != null);

        String javaHome = PropertyUtils.getSystemProperty("java.home");
        CACERTS_PATH =  javaHome + "/lib/security/cacerts".replace('/', File.separatorChar);
        JSSECACERTS_PATH =  javaHome + "/lib/security/jssecacerts".replace('/', File.separatorChar);
    }

    protected final Provider pkixProvider;

    protected X509TrustManager trustManager;

    public ProvTrustManagerFactorySpi(Provider pkixProvider)
    {
        this.pkixProvider = pkixProvider;
    }

    protected TrustManager[] engineGetTrustManagers()
    {
        return new TrustManager[]{ trustManager };
    }

    protected void engineInit(KeyStore ks)
        throws KeyStoreException
    {
        try
        {
            if (ks == null)
            {
                String tsType = PropertyUtils.getSystemProperty("javax.net.ssl.trustStoreType");
                if (tsType == null)
                {
                    tsType = KeyStore.getDefaultType();
                }

                ks = KeyStore.getInstance(tsType);

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
                    tsPath = JSSECACERTS_PATH;
                }
                else if (new File(CACERTS_PATH).exists())
                {
                    tsPath = CACERTS_PATH;
                }

                if (tsPath == null)
                {
                    ks.load(null, null);
                }
                else
                {
                    InputStream tsInput = new BufferedInputStream(new FileInputStream(tsPath));
                    ks.load(tsInput, tsPassword);
                    tsInput.close();
                }
            }
    
            if (hasExtendedTrustManager)
            {
                trustManager = new ProvX509ExtendedTrustManager(new ProvX509TrustManager(pkixProvider, ks));
            }
            else
            {
                trustManager = new ProvX509TrustManager(pkixProvider, ks);
            }
        }
        catch (Exception e)
        {
            throw new KeyStoreException("initialization failed", e);
        }
    }

    protected void engineInit(ManagerFactoryParameters spec)
        throws InvalidAlgorithmParameterException
    {
        throw new UnsupportedOperationException();
    }
}
