package org.bouncycastle.est;


/**
 * Build a RFC7030 client.
 */
public class ESTServiceBuilder
{

    protected TLSHostNameAuthorizer hostNameAuthorizer;
    final protected String server;
    protected TLSAuthorizer tlsAuthorizer;
    protected ESTClientProvider clientProvider;

    public ESTServiceBuilder(String server)
    {
        this.server = server;
    }



    public ESTServiceBuilder withHostNameAuthorizer(TLSHostNameAuthorizer hostNameAuthorizer)
    {
        this.hostNameAuthorizer = hostNameAuthorizer;
        return this;
    }

    public ESTServiceBuilder withTlsAuthorizer(TLSAuthorizer tlsAuthorizer)
    {
        this.tlsAuthorizer = tlsAuthorizer;
        return this;
    }


    public ESTServiceBuilder withClientProvider(ESTClientProvider clientProvider)
    {
        this.clientProvider = clientProvider;
        return this;
    }

    public ESTService build()
    {
        return new ESTService(
            hostNameAuthorizer,
            server,
            tlsAuthorizer,
            clientProvider);
    }

}



