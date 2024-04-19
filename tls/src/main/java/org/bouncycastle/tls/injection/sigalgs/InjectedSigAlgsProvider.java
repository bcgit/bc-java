package org.bouncycastle.tls.injection.sigalgs;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.tls.injection.InjectionPoint;

public class InjectedSigAlgsProvider
        extends Provider
        implements ConfigurableProvider
{
    private static String info = "TLS Injection Mechanism (TLS-IM) Provider for Injected Signature Algorithms";

    public static String PROVIDER_NAME = "TLS-IM";

    public static final ProviderConfiguration CONFIGURATION = null;


    private static final Map keyInfoConverters = new HashMap();

    public InjectedSigAlgsProvider()
    {
        super(PROVIDER_NAME, 1.0, info);

        AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                InjectionPoint.configureProvider(InjectedSigAlgsProvider.this);
                return null;
            }
        });
    }


    public void setParameter(
            String parameterName,
            Object parameter)
    {
        synchronized (CONFIGURATION)
        {
            //((BouncyCastleProviderConfiguration)CONFIGURATION).setParameter(parameterName, parameter);
        }
    }

    public boolean hasAlgorithm(
            String type,
            String name)
    {
        return containsKey(type + "." + name) || containsKey("Alg.Alias." + type + "." + name);
    }

    public void addAlgorithm(
            String key,
            String value)
    {
        if (containsKey(key))
        {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }

        put(key, value);
    }

    public void addAlgorithm(
            String key,
            String value,
            Map<String, String> attributes)
    {
        addAlgorithm(key, value);
        addAttributes(key, attributes);
    }

    public void addAlgorithm(
            String type,
            ASN1ObjectIdentifier oid,
            String className)
    {
        if (!containsKey(type + "." + className))
        {
            throw new IllegalStateException("primary key (" + type + "." + className + ") not found");
        }

        addAlgorithm(type + "." + oid, className);
        addAlgorithm(type + ".OID." + oid, className);
    }

    public void addAlgorithm(
            String type,
            ASN1ObjectIdentifier oid,
            String className,
            Map<String, String> attributes)
    {
        addAlgorithm(type, oid, className);
        addAttributes(type + "." + oid, attributes);
        addAttributes(type + ".OID." + oid, attributes);
    }

    public void addKeyInfoConverter(
            ASN1ObjectIdentifier oid,
            AsymmetricKeyInfoConverter keyInfoConverter)
    {
        synchronized (keyInfoConverters)
        {
            keyInfoConverters.put(oid, keyInfoConverter);
        }
    }

    public AsymmetricKeyInfoConverter getKeyInfoConverter(ASN1ObjectIdentifier oid)
    {
        return (AsymmetricKeyInfoConverter) keyInfoConverters.get(oid);
    }

    public void addAttributes(
            String key,
            Map<String, String> attributeMap)
    {
        for (Iterator it = attributeMap.keySet().iterator(); it.hasNext(); )
        {
            String attributeName = (String) it.next();
            String attributeKey = key + " " + attributeName;
            if (containsKey(attributeKey))
            {
                throw new IllegalStateException("duplicate provider attribute key (" + attributeKey + ") found");
            }

            put(attributeKey, attributeMap.get(attributeName));
        }
    }

    private static AsymmetricKeyInfoConverter getAsymmetricKeyInfoConverter(ASN1ObjectIdentifier algorithm)
    {
        synchronized (keyInfoConverters)
        {
            return (AsymmetricKeyInfoConverter) keyInfoConverters.get(algorithm);
        }
    }

    public static PublicKey getPublicKey(SubjectPublicKeyInfo publicKeyInfo)
            throws IOException
    {
        AsymmetricKeyInfoConverter converter = getAsymmetricKeyInfoConverter(publicKeyInfo.getAlgorithm().getAlgorithm());

        if (converter == null)
        {
            return null;
        }

        return converter.generatePublic(publicKeyInfo);
    }

    public static PrivateKey getPrivateKey(PrivateKeyInfo privateKeyInfo)
            throws IOException
    {
        AsymmetricKeyInfoConverter converter = getAsymmetricKeyInfoConverter(privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm());

        if (converter == null)
        {
            return null;
        }

        return converter.generatePrivate(privateKeyInfo);
    }

    static Class loadClass(
            Class sourceClass,
            final String className)
    {
        try
        {
            ClassLoader loader = sourceClass.getClassLoader();
            if (loader != null)
            {
                return loader.loadClass(className);
            }
            else
            {
                return (Class) AccessController.doPrivileged(new PrivilegedAction()
                {
                    public Object run()
                    {
                        try
                        {
                            return Class.forName(className);
                        } catch (Exception e)
                        {
                            // ignore - maybe log?
                        }

                        return null;
                    }
                });
            }
        } catch (ClassNotFoundException e)
        {
            // ignore - maybe log?
        }

        return null;
    }
}
