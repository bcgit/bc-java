package org.bouncycastle.est.jcajce;


import java.net.Socket;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.KeyManager;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.est.ESTClientProvider;
import org.bouncycastle.est.ESTService;
import org.bouncycastle.est.ESTServiceBuilder;


/**
 * Build an RFC7030 (EST) service based on the JSSE.
 */
public class JsseESTServiceBuilder
    extends ESTServiceBuilder
{
    protected SSLSocketFactoryCreator socketFactoryCreator;
    protected JsseHostnameAuthorizer hostNameAuthorizer = new JsseDefaultHostnameAuthorizer(null);
    protected int timeoutMillis = 0;
    protected ChannelBindingProvider bindingProvider;
    protected Set<String> supportedSuites = new HashSet<String>();
    protected Long absoluteLimit;
    protected SSLSocketFactoryCreatorBuilder sslSocketFactoryCreatorBuilder;
    protected boolean filterCipherSuites = true;

    /**
     * Create a builder for a client using a custom SSLSocketFactoryCreator.
     *
     * @param hostName             hostName to talk to.
     * @param socketFactoryCreator a custom creator of socket factories.
     */
    public JsseESTServiceBuilder(String hostName, int portNo, SSLSocketFactoryCreator socketFactoryCreator)
    {
        super(hostName + ":" + portNo);
        if (socketFactoryCreator == null)
        {
            throw new NullPointerException("No socket factory creator.");
        }
        this.socketFactoryCreator = socketFactoryCreator;
    }

    /**
     * Create a builder for a client using a custom SSLSocketFactoryCreator.
     *
     * @param server               name of the server to talk to (URL format).
     * @param socketFactoryCreator a custom creator of socket factories.
     */
    public JsseESTServiceBuilder(String server, SSLSocketFactoryCreator socketFactoryCreator)
    {
        super(server);
        if (socketFactoryCreator == null)
        {
            throw new NullPointerException("No socket factory creator.");
        }
        this.socketFactoryCreator = socketFactoryCreator;
    }

    /**
     * Create a builder for a client talking to a server that is not yet trusted.
     *
     * @param server name of the server to talk to (URL format).
     */
    public JsseESTServiceBuilder(String server)
    {
        super(server);
        sslSocketFactoryCreatorBuilder = new SSLSocketFactoryCreatorBuilder(JcaJceUtils.getTrustAllTrustManager());
    }

    /**
     * Create a builder for a client talking to a trusted server.
     *
     * @param hostName     name of the server to talk to.
     * @param portNo       port number to connect on.
     * @param trustManager trust manager to be used for validating the connection.
     */
    public JsseESTServiceBuilder(String hostName, int portNo, X509TrustManager trustManager)
    {
        super(hostName + ":" + portNo);
        sslSocketFactoryCreatorBuilder = new SSLSocketFactoryCreatorBuilder(trustManager);
    }

    /**
     * Create a builder for a client talking to a trusted server.
     *
     * @param server       name of the server to talk to (URL format).
     * @param trustManager trust manager to be used for validating the connection.
     */
    public JsseESTServiceBuilder(String server, X509TrustManager trustManager)
    {
        super(server);
        sslSocketFactoryCreatorBuilder = new SSLSocketFactoryCreatorBuilder(trustManager);
    }

    /**
     * Create a builder for a client talking to a trusted server.
     *
     * @param hostName      name of the server to talk to.
     * @param portNo        port number to connect on.
     * @param trustManagers trust managers that can be used for validating the connection.
     */
    public JsseESTServiceBuilder(String hostName, int portNo, X509TrustManager[] trustManagers)
    {
        this(hostName + ":" + portNo, trustManagers);
    }

    /**
     * Create a builder for a client talking to a trusted server.
     *
     * @param server       name of the server to talk to (URL format).
     * @param trustManagers trust managers that can be used for validating the connection.
     */
    public JsseESTServiceBuilder(String server, X509TrustManager[] trustManagers)
    {
        super(server);
        sslSocketFactoryCreatorBuilder = new SSLSocketFactoryCreatorBuilder(trustManagers);
    }

    public JsseESTServiceBuilder withHostNameAuthorizer(JsseHostnameAuthorizer hostNameAuthorizer)
    {
        this.hostNameAuthorizer = hostNameAuthorizer;
        return this;
    }

    public JsseESTServiceBuilder withClientProvider(ESTClientProvider clientProvider)
    {
        this.clientProvider = clientProvider;
        return this;
    }

    public JsseESTServiceBuilder withTimeout(int timeoutMillis)
    {
        this.timeoutMillis = timeoutMillis;
        return this;
    }

    public JsseESTServiceBuilder withReadLimit(long absoluteLimit)
    {
        this.absoluteLimit = absoluteLimit;
        return this;
    }


    public JsseESTServiceBuilder withChannelBindingProvider(ChannelBindingProvider channelBindingProvider)
    {
        this.bindingProvider = channelBindingProvider;
        return this;
    }

    public JsseESTServiceBuilder addCipherSuites(String name)
    {
        this.supportedSuites.add(name);
        return this;
    }

    public JsseESTServiceBuilder addCipherSuites(String[] names)
    {
        this.supportedSuites.addAll(Arrays.asList(names));
        return this;
    }

    public JsseESTServiceBuilder withTLSVersion(String tlsVersion)
    {
        if (this.socketFactoryCreator != null)
        {
            throw new IllegalStateException("Socket Factory Creator was defined in the constructor.");
        }

        this.sslSocketFactoryCreatorBuilder.withTLSVersion(tlsVersion);


        return this;
    }

    public JsseESTServiceBuilder withSecureRandom(SecureRandom secureRandom)
    {
        if (this.socketFactoryCreator != null)
        {
            throw new IllegalStateException("Socket Factory Creator was defined in the constructor.");
        }

        this.sslSocketFactoryCreatorBuilder.withSecureRandom(secureRandom);


        return this;
    }

    /**
     * Configure this builder to use the provider with the passed in name.
     *
     * @param tlsProviderName the name JSSE Provider to use.
     * @return the current builder instance.
     * @throws NoSuchProviderException if the specified provider does not exist.
     */
    public JsseESTServiceBuilder withProvider(String tlsProviderName)
        throws NoSuchProviderException
    {
        if (this.socketFactoryCreator != null)
        {
            throw new IllegalStateException("Socket Factory Creator was defined in the constructor.");
        }

        this.sslSocketFactoryCreatorBuilder.withProvider(tlsProviderName);

        return this;
    }

    /**
     * Configure this builder to use the passed in provider.
     *
     * @param tlsProvider the JSSE Provider to use.
     * @return the current builder instance.
     */
    public JsseESTServiceBuilder withProvider(Provider tlsProvider)
    {
        if (this.socketFactoryCreator != null)
        {
            throw new IllegalStateException("Socket Factory Creator was defined in the constructor.");
        }

        this.sslSocketFactoryCreatorBuilder.withProvider(tlsProvider);
        return this;
    }

    public JsseESTServiceBuilder withKeyManager(KeyManager keyManager)
    {
        if (this.socketFactoryCreator != null)
        {
            throw new IllegalStateException("Socket Factory Creator was defined in the constructor.");
        }

        this.sslSocketFactoryCreatorBuilder.withKeyManager(keyManager);
        return this;
    }

    public JsseESTServiceBuilder withKeyManagers(KeyManager[] keyManagers)
    {
        if (this.socketFactoryCreator != null)
        {
            throw new IllegalStateException("Socket Factory Creator was defined in the constructor.");
        }
        this.sslSocketFactoryCreatorBuilder.withKeyManagers(keyManagers);
        return this;
    }

    /**
     * Filter cipher suites with supported before passing to JSSE provider.
     *
     * @param filter true, supplied cipher suites will be filtered with supported before passing to the JSSE provider.
     * @return this;
     */
    public JsseESTServiceBuilder withFilterCipherSuites(boolean filter)
    {
        this.filterCipherSuites = filter;
        return this;
    }

    public ESTService build()
    {
        if (bindingProvider == null)
        {
            bindingProvider = new ChannelBindingProvider()
            {
                public boolean canAccessChannelBinding(Socket sock)
                {
                    return false;
                }

                public byte[] getChannelBinding(Socket sock, String binding)
                {
                    return null;
                }
            };
        }

        if (socketFactoryCreator == null)
        {
            socketFactoryCreator = sslSocketFactoryCreatorBuilder.build();
        }


        if (clientProvider == null)
        {
            clientProvider = new DefaultESTHttpClientProvider(
                hostNameAuthorizer,
                socketFactoryCreator,
                timeoutMillis,
                bindingProvider,
                supportedSuites,
                absoluteLimit, filterCipherSuites);
        }

        return super.build();
    }

}



