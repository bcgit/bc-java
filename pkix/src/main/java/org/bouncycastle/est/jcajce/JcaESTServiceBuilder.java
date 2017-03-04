package org.bouncycastle.est.jcajce;


import java.net.Socket;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.SSLSession;

import org.bouncycastle.est.ESTClientProvider;
import org.bouncycastle.est.ESTService;
import org.bouncycastle.est.ESTServiceBuilder;


/**
 * Build a RFC7030 client.
 */
public class JcaESTServiceBuilder
    extends ESTServiceBuilder
{
    protected final SSLSocketFactoryCreator socketFactoryCreator;
    protected HostnameAuthorizer<SSLSession> hostNameAuthorizer = new DefaultHostnameVerifier();
    protected int timeoutMillis = 0;
    protected ChannelBindingProvider bindingProvider;
    protected Set<String> supportedSuites = new HashSet<String>();
    protected Long absoluteLimit;


    /**
     * Create a builder for a client talking to a already trusted server.
     *
     * @param server               name of the server to talk to (URL format).
     * @param socketFactoryCreator creator of socket factories.
     */
    public JcaESTServiceBuilder(String server, SSLSocketFactoryCreator socketFactoryCreator)
    {
        super(server);
        if (socketFactoryCreator == null)
        {
            throw new IllegalArgumentException("No socket factory creator.");
        }
        this.socketFactoryCreator = socketFactoryCreator;

    }


    public JcaESTServiceBuilder withHostNameAuthorizer(HostnameAuthorizer hostNameAuthorizer)
    {
        this.hostNameAuthorizer = hostNameAuthorizer;
        return this;
    }

    public JcaESTServiceBuilder withClientProvider(ESTClientProvider clientProvider)
    {
        this.clientProvider = clientProvider;
        return this;
    }


    public JcaESTServiceBuilder withTimeout(int timeoutMillis)
    {
        this.timeoutMillis = timeoutMillis;
        return this;
    }

    public JcaESTServiceBuilder withReadLimit(long absoluteLimit)
    {
        this.absoluteLimit = absoluteLimit;
        return this;
    }


    public JcaESTServiceBuilder withChannelBindingProvider(ChannelBindingProvider channelBindingProvider)
    {
        this.bindingProvider = channelBindingProvider;
        return this;
    }

    public JcaESTServiceBuilder addCipherSuites(String name)
    {
        this.supportedSuites.add(name);
        return this;
    }

    public JcaESTServiceBuilder addCipherSuites(String[] names)
    {
        this.supportedSuites.addAll(Arrays.asList(names));
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

        if (clientProvider == null)
        {
            clientProvider = new JcaDefaultESTHttpClientProvider(
                hostNameAuthorizer,
                socketFactoryCreator,
                timeoutMillis,
                bindingProvider,
                supportedSuites,
                absoluteLimit);
        }

        return super.build();
    }

}



