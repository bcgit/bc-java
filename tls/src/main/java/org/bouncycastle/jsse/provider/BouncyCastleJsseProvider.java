package org.bouncycastle.jsse.provider;

import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;
import org.bouncycastle.util.Strings;

@SuppressWarnings("serial")
public class BouncyCastleJsseProvider
    extends Provider
{
    public static final String PROVIDER_NAME = "BCJSSE";

    private static final String JSSE_CONFIG_PROPERTY = "org.bouncycastle.jsse.config";

    private static final double PROVIDER_VERSION = 1.0022;
    private static final String PROVIDER_INFO = "Bouncy Castle JSSE Provider Version 1.0.22";

    private final Map<String, BcJsseService> serviceMap = new ConcurrentHashMap<String, BcJsseService>();
    private final Map<String, EngineCreator> creatorMap = new HashMap<String, EngineCreator>();

    private final boolean configFipsMode;
    private final JcaTlsCryptoProvider configCryptoProvider;

    public BouncyCastleJsseProvider()
    {
        this(getPropertyValue(JSSE_CONFIG_PROPERTY, "default"));
    }

    public BouncyCastleJsseProvider(boolean fipsMode)
    {
        super(PROVIDER_NAME, PROVIDER_VERSION, PROVIDER_INFO);

        this.configFipsMode = fipsMode;
        this.configCryptoProvider = new JcaTlsCryptoProvider();

        configure();
    }

    public BouncyCastleJsseProvider(Provider provider)
    {
        this(false, provider);
    }

    public BouncyCastleJsseProvider(boolean fipsMode, Provider provider)
    {
        super(PROVIDER_NAME, PROVIDER_VERSION, PROVIDER_INFO);

        this.configFipsMode = fipsMode;
        this.configCryptoProvider = new JcaTlsCryptoProvider().setProvider(provider);

        configure();
    }

    public BouncyCastleJsseProvider(String config)
    {
        super(PROVIDER_NAME, PROVIDER_VERSION, PROVIDER_INFO);

        config = config.trim();

        boolean fipsMode = false;
        String cryptoName = config;
        String altCryptoName = null;

        int colonPos = config.indexOf(':');
        if (colonPos >= 0)
        {
            String first = config.substring(0, colonPos).trim();
            String second = config.substring(colonPos + 1).trim();

            fipsMode = first.equalsIgnoreCase("fips");
            config = second;
        }

        int commaPos = config.indexOf(',');
        if (commaPos >= 0)
        {
            cryptoName = config.substring(0, commaPos).trim();
            altCryptoName = config.substring(commaPos + 1).trim();
        }
        else
        {
            cryptoName = config;
        }

        JcaTlsCryptoProvider cryptoProvider;
        try
        {
            cryptoProvider = createCryptoProvider(cryptoName, altCryptoName);
        }
        catch (GeneralSecurityException e)
        {
            throw new IllegalArgumentException("unable to set up JcaTlsCryptoProvider: " + e.getMessage(), e);
        }

        this.configFipsMode = fipsMode;
        this.configCryptoProvider = cryptoProvider;

        configure();
    }

    public BouncyCastleJsseProvider(boolean fipsMode, JcaTlsCryptoProvider cryptoProvider)
    {
        super(PROVIDER_NAME, PROVIDER_VERSION, PROVIDER_INFO);

        this.configFipsMode = fipsMode;
        this.configCryptoProvider = cryptoProvider;

        configure();
    }

    // for Java 11
    public Provider configure(String configArg)
    {
        return new BouncyCastleJsseProvider(configArg);
    }

    private JcaTlsCryptoProvider createCryptoProvider(String cryptoName, String altCryptoName)
        throws GeneralSecurityException
    {
        if (cryptoName.equalsIgnoreCase("default"))
        {
            return new JcaTlsCryptoProvider();
        }

        Provider provider = Security.getProvider(cryptoName);
        if (provider != null)
        {
            JcaTlsCryptoProvider cryptoProvider = new JcaTlsCryptoProvider().setProvider(provider);

            if (altCryptoName != null)
            {
                // this has to be done by name as a PKCS#11 login may be required.
                cryptoProvider.setAlternateProvider(altCryptoName);
            }

            return cryptoProvider;
        }

        // TODO: should we support alt name here?
        try
        {
            Class<?> cryptoProviderClass = Class.forName(cryptoName);

            // the TlsCryptoProvider/Provider class named requires a no-args constructor
            Object cryptoProviderInstance = cryptoProviderClass.newInstance();

            if (cryptoProviderInstance instanceof JcaTlsCryptoProvider)
            {
                return (JcaTlsCryptoProvider)cryptoProviderInstance;
            }

            if (cryptoProviderInstance instanceof Provider)
            {
                return new JcaTlsCryptoProvider().setProvider((Provider)cryptoProviderInstance);
            }

            throw new IllegalArgumentException("unrecognized class: " + cryptoName);
        }
        catch (ClassNotFoundException e)
        {
            throw new IllegalArgumentException("unable to find Provider/JcaTlsCryptoProvider class: " + cryptoName);
        }
        catch (InstantiationException e)
        {
            throw new IllegalArgumentException("unable to create Provider/JcaTlsCryptoProvider class '" + cryptoName + "': " + e.getMessage(), e);
        }
        catch (IllegalAccessException e)
        {
            throw new IllegalArgumentException("unable to create Provider/JcaTlsCryptoProvider class '" + cryptoName + "': " + e.getMessage(), e);
        }
    }

    private void configure()
    {
        final boolean fipsMode = configFipsMode;
        final JcaTlsCryptoProvider cryptoProvider = configCryptoProvider;

        // TODO[jsse]: should X.509 be an alias.
        addAlgorithmImplementation("KeyManagerFactory.X.509", "org.bouncycastle.jsse.provider.KeyManagerFactory", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ProvKeyManagerFactorySpi(fipsMode, cryptoProvider.getHelper());
            }
        });
        addAlias("Alg.Alias.KeyManagerFactory.X509", "X.509");
        addAlias("Alg.Alias.KeyManagerFactory.PKIX", "X.509");

        addAlgorithmImplementation("TrustManagerFactory.PKIX", "org.bouncycastle.jsse.provider.TrustManagerFactory", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ProvTrustManagerFactorySpi(fipsMode, cryptoProvider.getHelper());
            }
        });
        addAlias("Alg.Alias.TrustManagerFactory.X.509", "PKIX");
        addAlias("Alg.Alias.TrustManagerFactory.X509", "PKIX");

        addAlgorithmImplementation("SSLContext.TLS", "org.bouncycastle.jsse.provider.SSLContext.TLS",
            new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new ProvSSLContextSpi(fipsMode, cryptoProvider, null);
                }
            });
        addAlgorithmImplementation("SSLContext.TLSV1", "org.bouncycastle.jsse.provider.SSLContext.TLSv1",
            new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new ProvSSLContextSpi(fipsMode, cryptoProvider, specifyClientProtocols("TLSv1"));
                }
            });
        addAlgorithmImplementation("SSLContext.TLSV1.1", "org.bouncycastle.jsse.provider.SSLContext.TLSv1_1",
            new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new ProvSSLContextSpi(fipsMode, cryptoProvider, specifyClientProtocols("TLSv1.1", "TLSv1"));
                }
            });
        addAlgorithmImplementation("SSLContext.TLSV1.2", "org.bouncycastle.jsse.provider.SSLContext.TLSv1_2",
            new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new ProvSSLContextSpi(fipsMode, cryptoProvider,
                        specifyClientProtocols("TLSv1.2", "TLSv1.1", "TLSv1"));
                }
            });
        addAlgorithmImplementation("SSLContext.TLSV1.3", "org.bouncycastle.jsse.provider.SSLContext.TLSv1_3",
            new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new ProvSSLContextSpi(fipsMode, cryptoProvider,
                        specifyClientProtocols("TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1"));
                }
            });
        addAlgorithmImplementation("SSLContext.DEFAULT", "org.bouncycastle.jsse.provider.SSLContext.Default",
            new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                    throws GeneralSecurityException
                {
                    return new DefaultSSLContextSpi(fipsMode, cryptoProvider);
                }
            });
        addAlias("Alg.Alias.SSLContext.SSL", "TLS");
        addAlias("Alg.Alias.SSLContext.SSLV3", "TLSV1");
    }

    void addAttribute(String key, String attributeName, String attributeValue)
    {
        String attributeKey = key + " " + attributeName;
        if (containsKey(attributeKey))
        {
            throw new IllegalStateException("duplicate provider attribute key (" + attributeKey + ") found");
        }

        doPut(attributeKey, attributeValue);
    }

    void addAlgorithmImplementation(String key, String className, EngineCreator creator)
    {
        if (containsKey(key))
        {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }

        addAttribute(key, "ImplementedIn", "Software");

        doPut(key, className);
        creatorMap.put(className, creator);
    }

    void addAlias(String key, String value)
    {
        if (containsKey(key))
        {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }

        doPut(key, value);
    }

    public final Provider.Service getService(String type, String algorithm)
    {
        String upperCaseAlgName = Strings.toUpperCase(algorithm);
        String serviceKey = type + "." + upperCaseAlgName;

        BcJsseService service = serviceMap.get(serviceKey);

        if (service == null)
        {
            String aliasString = "Alg.Alias." + type + ".";
            String realName = (String)this.get(aliasString + upperCaseAlgName);

            if (realName == null)
            {
                realName = upperCaseAlgName;
            }

            String className = (String)this.get(type + "." + realName);

            if (className == null)
            {
                return null;
            }

            String attributeKeyStart = type + "." + realName + " ";

            List<String> aliases = new ArrayList<String>();
            Map<String, String> attributes = new HashMap<String, String>();

            for (Object key : this.keySet())
            {
                String sKey = (String)key;
                if (sKey.startsWith(aliasString))
                {
                    if (this.get(key).equals(algorithm))
                    {
                        aliases.add(sKey.substring(aliasString.length()));
                    }
                }
                if (sKey.startsWith(attributeKeyStart))
                {
                    attributes.put(sKey.substring(attributeKeyStart.length()), (String)this.get(sKey));
                }
            }

            synchronized (this)
            {
                if (!serviceMap.containsKey(serviceKey))
                {
                    service = new BcJsseService(this, type, upperCaseAlgName, className, aliases, getAttributeMap(attributes), creatorMap.get(className));

                    serviceMap.put(serviceKey, service);
                }
                else
                {
                    service = serviceMap.get(serviceKey);
                }
            }
        }

        return service;
    }

    public synchronized final Set<Provider.Service> getServices()
    {
        Set<Provider.Service> serviceSet = super.getServices();
        Set<Provider.Service> bcServiceSet = new HashSet<Provider.Service>();

        for (Provider.Service service : serviceSet)
        {
            bcServiceSet.add(getService(service.getType(), service.getAlgorithm()));
        }

        return bcServiceSet;
    }

    private static final Map<Map<String, String>, Map<String, String>> attributeMaps = new HashMap<Map<String, String>, Map<String, String>>();

    private static synchronized Map<String, String> getAttributeMap(Map<String, String> attributeMap)
    {
        Map<String, String> attrMap = attributeMaps.get(attributeMap);
        if (attrMap != null)
        {
            return attrMap;
        }

        attributeMaps.put(attributeMap, attributeMap);

        return attributeMap;
    }

    private Object doPut(final String key, final String value)
    {
        return AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                return put(key, value);
            }
        });
    }

    private static List<String> specifyClientProtocols(String... protocols)
    {
        return Arrays.asList(protocols);
    }

    public boolean isFipsMode()
    {
        return configFipsMode;
    }

    private static class BcJsseService
        extends Provider.Service
    {
        private final EngineCreator creator;

        /**
         * Construct a new service.
         *
         * @param provider   the provider that offers this service
         * @param type       the type of this service
         * @param algorithm  the algorithm name
         * @param className  the name of the class implementing this service
         * @param aliases    List of aliases or null if algorithm has no aliases
         * @param attributes Map of attributes or null if this implementation
         *                   has no attributes
         * @throws NullPointerException if provider, type, algorithm, or
         *                              className is null
         */
        public BcJsseService(Provider provider, String type, String algorithm, String className, List<String> aliases, Map<String, String> attributes, EngineCreator creator)
        {
            super(provider, type, algorithm, className, aliases, attributes);
            this.creator = creator;
        }

        public Object newInstance(Object constructorParameter)
            throws NoSuchAlgorithmException
        {
            try
            {
                Object instance = creator.createInstance(constructorParameter);

                if (instance == null)
                {
                    throw new NoSuchAlgorithmException("No such algorithm in FIPS approved mode: " + getAlgorithm());
                }

                return instance;
            }
            catch (NoSuchAlgorithmException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new NoSuchAlgorithmException("Unable to invoke creator for " + getAlgorithm() + ": " + e.getMessage(), e);
            }
        }
    }

    // added here as not present in FIPS yet.
    private static String getPropertyValue(final String propertyName, final String defValue)
    {
        return AccessController.doPrivileged(new PrivilegedAction<String>()
        {
            public String run()
            {
                String v = Security.getProperty(propertyName);
                if (v != null)
                {
                    return v;
                }
                v = System.getProperty(propertyName);
                if (v != null)
                {
                    return v;
                }
                return defValue;
            }
        });
    }
}
