package org.bouncycastle.pqc.jcajce.provider;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

public class BouncyCastlePQCProvider
    extends Provider
    implements ConfigurableProvider
{
    private static String info = "BouncyCastle Post-Quantum Security Provider v1.56";

    public static String PROVIDER_NAME = "BCPQC";

    public static final ProviderConfiguration CONFIGURATION = null;


    private static final Map keyInfoConverters = new HashMap();

    /*
    * Configurable symmetric ciphers
    */
    private static final String ALGORITHM_PACKAGE = "org.bouncycastle.pqc.jcajce.provider.";
    private static final String[] ALGORITHMS =
        {
            "Rainbow", "McEliece", "SPHINCS", "NH"
        };

    /**
     * Construct a new provider.  This should only be required when
     * using runtime registration of the provider using the
     * <code>Security.addProvider()</code> mechanism.
     */
    public BouncyCastlePQCProvider()
    {
        super(PROVIDER_NAME, 1.56, info);

        AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                setup();
                return null;
            }
        });
    }

    private void setup()
    {
        loadAlgorithms(ALGORITHM_PACKAGE, ALGORITHMS);
    }

    private void loadAlgorithms(String packageName, String[] names)
    {
        for (int i = 0; i != names.length; i++)
        {
            Class clazz = null;
            try
            {
                ClassLoader loader = this.getClass().getClassLoader();

                if (loader != null)
                {
                    clazz = loader.loadClass(packageName + names[i] + "$Mappings");
                }
                else
                {
                    clazz = Class.forName(packageName + names[i] + "$Mappings");
                }
            }
            catch (ClassNotFoundException e)
            {
                // ignore
            }

            if (clazz != null)
            {
                try
                {
                    ((AlgorithmProvider)clazz.newInstance()).configure(this);
                }
                catch (Exception e)
                {   // this should never ever happen!!
                    throw new InternalError("cannot create instance of "
                        + packageName + names[i] + "$Mappings : " + e);
                }
            }
        }
    }

    public void setParameter(String parameterName, Object parameter)
    {
        synchronized (CONFIGURATION)
        {
            //((BouncyCastleProviderConfiguration)CONFIGURATION).setParameter(parameterName, parameter);
        }
    }

    public boolean hasAlgorithm(String type, String name)
    {
        return containsKey(type + "." + name) || containsKey("Alg.Alias." + type + "." + name);
    }

    public void addAlgorithm(String key, String value)
    {
        if (containsKey(key))
        {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }

        put(key, value);
    }

    public void addAlgorithm(String type,  ASN1ObjectIdentifier oid, String className)
    {
        if (!containsKey(type + "." + className))
        {
            throw new IllegalStateException("primary key (" + type + "." + className + ") not found");
        }

        addAlgorithm(type + "." + oid, className);
        addAlgorithm(type + ".OID." + oid, className);
    }

    public void addKeyInfoConverter(ASN1ObjectIdentifier oid, AsymmetricKeyInfoConverter keyInfoConverter)
    {
        synchronized (keyInfoConverters)
        {
            keyInfoConverters.put(oid, keyInfoConverter);
        }
    }

    private static AsymmetricKeyInfoConverter getAsymmetricKeyInfoConverter(ASN1ObjectIdentifier algorithm)
    {
        synchronized (keyInfoConverters)
        {
            return (AsymmetricKeyInfoConverter)keyInfoConverters.get(algorithm);
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
}
