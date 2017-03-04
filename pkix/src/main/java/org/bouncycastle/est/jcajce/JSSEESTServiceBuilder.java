package org.bouncycastle.est.jcajce;


import java.net.Socket;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.est.ESTClientProvider;
import org.bouncycastle.est.ESTService;
import org.bouncycastle.est.ESTServiceBuilder;


/**
 * Build a RFC7030 client.
 */
public class JSSEESTServiceBuilder
    extends ESTServiceBuilder
{
    protected final SSLSocketFactoryCreator socketFactoryCreator;
    protected JSSEHostnameAuthorizer hostNameAuthorizer = new DefaultHostnameVerifier();
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
    public JSSEESTServiceBuilder(String server, SSLSocketFactoryCreator socketFactoryCreator)
    {
        super(server);
        if (socketFactoryCreator == null)
        {
            throw new IllegalArgumentException("No socket factory creator.");
        }
        this.socketFactoryCreator = socketFactoryCreator;

    }


    public JSSEESTServiceBuilder withHostNameAuthorizer(JSSEHostnameAuthorizer hostNameAuthorizer)
    {
        this.hostNameAuthorizer = hostNameAuthorizer;
        return this;
    }

    public JSSEESTServiceBuilder withClientProvider(ESTClientProvider clientProvider)
    {
        this.clientProvider = clientProvider;
        return this;
    }


    public JSSEESTServiceBuilder withTimeout(int timeoutMillis)
    {
        this.timeoutMillis = timeoutMillis;
        return this;
    }

    public JSSEESTServiceBuilder withReadLimit(long absoluteLimit)
    {
        this.absoluteLimit = absoluteLimit;
        return this;
    }


    public JSSEESTServiceBuilder withChannelBindingProvider(ChannelBindingProvider channelBindingProvider)
    {
        this.bindingProvider = channelBindingProvider;
        return this;
    }

    public JSSEESTServiceBuilder addCipherSuites(String name)
    {
        this.supportedSuites.add(name);
        return this;
    }

    public JSSEESTServiceBuilder addCipherSuites(String[] names)
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
            clientProvider = new JSSEDefaultESTHttpClientProvider(
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



