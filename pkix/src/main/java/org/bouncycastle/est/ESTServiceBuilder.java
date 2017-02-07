package org.bouncycastle.est;


/**
 * Build a RFC7030 client.
 */
public class ESTServiceBuilder
{
    protected final String server;

    protected TLSHostNameAuthorizer hostNameAuthorizer;
    protected ESTAuthorizer ESTAuthorizer;
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

    public ESTServiceBuilder withTlsAuthorizer(ESTAuthorizer ESTAuthorizer)
    {
        this.ESTAuthorizer = ESTAuthorizer;
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
            ESTAuthorizer,
            clientProvider);
    }

}



