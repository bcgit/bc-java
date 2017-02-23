package org.bouncycastle.est.jcajce;


import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.CRL;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
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
    protected Set<TrustAnchor> tlsTrustAnchors;
    protected KeyStore clientKeystore;
    protected char[] clientKeystorePassword;
    protected JcaJceHostNameAuthorizer<SSLSession> hostNameAuthorizer;
    protected JcaJceAuthorizer ESTAuthorizer;
    protected CRL[] revocationLists;
    protected String tlsVersion = "TLS";
    protected int timeoutMillis = 0;
    protected String tlsProvider = null;
    protected ChannelBindingProvider bindingProvider;
    protected Set<String> supportedSuites = new HashSet<String>();
    private Long absoluteLimit;

    /**
     * Create a builder for a client talking to a server where trust anchors have not been established yet.
     *
     * @param server name of the server to talk to (URL format).
     */
    public JcaESTServiceBuilder(String server)
    {
        super(server);
        this.ESTAuthorizer = new JcaJceAuthorizer()
        {
            public void authorize(
                X509Certificate[] chain,
                String authType)
                throws CertificateException
            {
                // Does nothing, will accept any and all tendered certificates from the server.
            }
        };
    }

    /**
     * Create a builder for a client talking to a already trusted server.
     *
     * @param server          name of the server to talk to (URL format).
     * @param tlsTrustAnchors the trust anchor set to use to authenticate the server.
     */
    public JcaESTServiceBuilder(String server, Set<TrustAnchor> tlsTrustAnchors)
    {
        super(server);
        if (tlsTrustAnchors == null || tlsTrustAnchors.isEmpty())
        {
            //
            // You must set trust anchors to use this constructor, if you desire the service to accept
            // any server tendered certificates then use the alternative constructor.
            //
            throw new IllegalStateException("Trust anchors must be not null and not empty.");
        }
        this.tlsTrustAnchors = tlsTrustAnchors;
    }

    public JcaESTServiceBuilder withClientKeystore(KeyStore clientKeystore, char[] clientKeystorePassword)
    {
        this.clientKeystore = clientKeystore;
        this.clientKeystorePassword = clientKeystorePassword;
        return this;
    }

    public JcaESTServiceBuilder withHostNameAuthorizer(JcaJceHostNameAuthorizer hostNameAuthorizer)
    {
        this.hostNameAuthorizer = hostNameAuthorizer;
        return this;
    }

    public JcaESTServiceBuilder withRevocationLists(CRL[] revocationLists)
    {
        this.revocationLists = revocationLists;
        return this;
    }

    public JcaESTServiceBuilder withClientProvider(ESTClientProvider clientProvider)
    {
        this.clientProvider = clientProvider;
        return this;
    }

    public JcaESTServiceBuilder withTlsVersion(String tlsVersion)
    {
        this.tlsVersion = tlsVersion;
        return this;
    }

    public JcaESTServiceBuilder withTlSProvider(String tlsProvider)
    {
        this.tlsProvider = tlsProvider;
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

    public JcaESTServiceBuilder addCipherSuit(String name)
    {
        this.supportedSuites.add(name);
        return this;
    }

    public JcaESTServiceBuilder addCipherSuit(String[] names)
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
                tlsTrustAnchors,
                clientKeystore,
                clientKeystorePassword,
                hostNameAuthorizer,
                revocationLists,
                ESTAuthorizer,
                tlsVersion,
                tlsProvider,
                timeoutMillis,
                bindingProvider,
                supportedSuites, absoluteLimit);
        }

        return super.build();
    }

}



