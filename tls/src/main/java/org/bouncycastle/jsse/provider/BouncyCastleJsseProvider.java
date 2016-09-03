package org.bouncycastle.jsse.provider;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.tls.TlsCrypto;
import org.bouncycastle.tls.crypto.jcajce.JcaTlsCryptoBuilder;
import org.bouncycastle.util.Strings;

public class BouncyCastleJsseProvider
    extends Provider
{
    private Map<String, BcJsseService> serviceMap = new HashMap<String, BcJsseService>();
    private Map<String, EngineCreator> creatorMap = new HashMap<String, EngineCreator>();

    private boolean isInFipsMode;

    public BouncyCastleJsseProvider()
    {
        super("BCTLS", 0.9, "Bouncy Castle JSSE Provider");

        SecureRandom entropySource = new SecureRandom();
        
        configure(false, new JcaTlsCryptoBuilder(entropySource, entropySource).build());
    }

    public BouncyCastleJsseProvider(Provider provider)
    {
        this(false, provider);
    }

    public BouncyCastleJsseProvider(boolean isInFipsMode, Provider provider)
    {
        super("BCTLS", 0.9, "Bouncy Castle JSSE Provider");

        try
        {
            SecureRandom mainEntropy = SecureRandom.getInstance("DEFAULT", provider);

            configure(isInFipsMode, new JcaTlsCryptoBuilder(mainEntropy, SecureRandom.getInstance("NONCEANDIV", provider)).setProvider(provider).build());
        }
        catch (GeneralSecurityException e)
        {
            throw new IllegalArgumentException("unable to set up TlsCrypto: " + e.getMessage(), e);
        }
    }

    public BouncyCastleJsseProvider(String config)
    {
        super("BCTLS", 0.9, "Bouncy Castle JSSE Provider");

        boolean isFips = false;

        try
        {
            if (config.indexOf(':') > 0)
            {
                isFips = Boolean.valueOf(config.substring(0, config.indexOf(':')).trim());

                String cryptoName = config.substring(config.indexOf(':') + 1).trim();

                configure(isFips, createCrypto(cryptoName));
            }
            else
            {
                configure(isFips, createCrypto(config.trim()));
            }
        }
        catch (GeneralSecurityException e)
        {
            throw new IllegalArgumentException("unable to set up TlsCrypto: " + e.getMessage(), e);
        }
    }

    public BouncyCastleJsseProvider(boolean fipsMode, TlsCrypto tlsCrypto)
    {
        super("BCTLS", 0.9, "Bouncy Castle JSSE Provider");

        configure(fipsMode, tlsCrypto);
    }
    
    private TlsCrypto createCrypto(String cryptoName)
        throws GeneralSecurityException
    {
        if (cryptoName.equalsIgnoreCase("default"))
        {        
            SecureRandom mainEntropy = SecureRandom.getInstance("DEFAULT");

            return new JcaTlsCryptoBuilder(mainEntropy, SecureRandom.getInstance("NONCEANDIV")).build();
        }
        else
        {
            Provider provider = Security.getProvider(cryptoName);

            
            if (provider != null)
            { 
                SecureRandom mainEntropy = SecureRandom.getInstance("DEFAULT", provider);
                
                return new JcaTlsCryptoBuilder(mainEntropy, SecureRandom.getInstance("NONCEANDIV", provider)).build();
            }
            else
            {
                try
                {
                    Class cryptoClass = Class.forName(cryptoName);

                    // the TlsCrypto/Provider class named requires a no-args constructor
                    Object o = cryptoClass.newInstance();
                    if (o instanceof TlsCrypto)
                    {
                        return (TlsCrypto)o;
                    }
                    if (o instanceof Provider)
                    {
                        provider = (Provider)o;

                        SecureRandom mainEntropy = SecureRandom.getInstance("DEFAULT", provider);

                        return new JcaTlsCryptoBuilder(mainEntropy, SecureRandom.getInstance("NONCEANDIV", provider)).build();
                    }

                    throw new IllegalArgumentException("unrecognized class: " + cryptoName);
                }
                catch (ClassNotFoundException e)
                {
                    throw new IllegalArgumentException("unable to find Provider/TlsCrypto class: " + cryptoName);
                }
                catch (InstantiationException e)
                {
                    throw new IllegalArgumentException("unable to create Provider/TlsCrypto class '" + cryptoName + "': " + e.getMessage(), e);
                }
                catch (IllegalAccessException e)
                {
                    throw new IllegalArgumentException("unable to create Provider/TlsCrypto class '" + cryptoName + "': " + e.getMessage(), e);
                }
            }
        }
    }

    // TODO: add a real fips mode
    private void configure(boolean isInFipsMode, TlsCrypto baseCrypto)
    {
        this.isInFipsMode = isInFipsMode;

        addAlgorithmImplementation("KeyManagerFactory.X.509", "org.bouncycastle.jsse.provider.KeyManagerFactory", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ProvKeyManagerFactory();
            }
        });
        addAlias("Alg.Alias.KeyManagerFactory.X509", "X.509");
        addAlias("Alg.Alias.KeyManagerFactory.PKIX", "X.509");

        addAlgorithmImplementation("TrustManagerFactory.PKIX", "org.bouncycastle.jsse.provider.TrustManagerFactory", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ProvTrustManagerFactory();
            }
        });
        addAlias("Alg.Alias.TrustManagerFactory.X.509", "PKIX");
        addAlias("Alg.Alias.TrustManagerFactory.X509", "PKIX");

        if (isInFipsMode == false)
        {
            addAlgorithmImplementation("SSLContext.SSL", "org.bouncycastle.jsse.provider.SSLContext.TLS", new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new ProvSSLContext();
                }
            });
        }

        addAlgorithmImplementation("SSLContext.TLS", "org.bouncycastle.jsse.provider.SSLContext.TLS", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ProvSSLContext();
            }
        });
        addAlgorithmImplementation("SSLContext.TLSv1", "org.bouncycastle.jsse.provider.SSLContext.TLS.1", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ProvSSLContext();
            }
        });
        addAlgorithmImplementation("SSLContext.Default", "org.bouncycastle.jsse.provider.SSLContext.TLS.Default", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ProvSSLContext();
            }
        });
    }

    void addAttribute(String key, String attributeName, String attributeValue)
    {
        String attributeKey = key + " " + attributeName;
        if (containsKey(attributeKey))
        {
            throw new IllegalStateException("duplicate provider attribute key (" + attributeKey + ") found");
        }

        put(attributeKey, attributeValue);
    }

    void addAlgorithmImplementation(String key, String className, EngineCreator creator)
    {
        if (containsKey(key))
        {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }

        addAttribute(key, "ImplementedIn", "Software");

        put(key, className);
        creatorMap.put(className, creator);
    }

    void addAlias(String key, String value)
    {
        if (containsKey(key))
        {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }

        put(key, value);
    }

    public synchronized final Provider.Service getService(String type, String algorithm)
    {
        String upperCaseAlgName = Strings.toUpperCase(algorithm);

        BcJsseService service = serviceMap.get(type + "." + upperCaseAlgName);

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

            String attributeKeyStart = type + "." + upperCaseAlgName + " ";

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

            service = new BcJsseService(this, type, upperCaseAlgName, className, aliases, getAttributeMap(attributes), creatorMap.get(className));

            serviceMap.put(type + "." + upperCaseAlgName, service);
        }

        return service;
    }

    public synchronized final Set<Provider.Service> getServices()
    {
        Set<Provider.Service> serviceSet = super.getServices();
        Set<Provider.Service> bcServiceSet = new HashSet<Provider.Service>();

        for (Provider.Service service: serviceSet)
        {
            bcServiceSet.add(getService(service.getType(), service.getAlgorithm()));
        }

        return bcServiceSet;
    }

    private static final Map<Map<String, String>, Map<String, String> > attributeMaps = new HashMap<Map<String, String>, Map<String, String>>();

    private static Map<String, String> getAttributeMap(Map<String, String> attributeMap)
    {
        Map<String, String> attrMap = attributeMaps.get(attributeMap);
        if (attrMap != null)
        {
            return attrMap;
        }

        attributeMaps.put(attributeMap, attributeMap);

        return attributeMap;
    }

    public boolean isFipsMode()
    {
        return isInFipsMode;
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
         * className is null
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

    private class NonceAndIvSecureRandom
        extends SecureRandom
    {
        NonceAndIvSecureRandom(SecureRandomSpi secureRandomSpi)
        {
            super(secureRandomSpi, BouncyCastleJsseProvider.this);
        }
    }
}
