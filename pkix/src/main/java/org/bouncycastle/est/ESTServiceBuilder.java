package org.bouncycastle.est;


/**
 * Build an RFC7030 (EST) service.
 */
public class ESTServiceBuilder
{
    protected final String server;
    protected ESTClientProvider clientProvider;

    public ESTServiceBuilder(String server)
    {
        this.server = server;
    }


    public ESTServiceBuilder withClientProvider(ESTClientProvider clientProvider)
    {
        this.clientProvider = clientProvider;
        return this;
    }

    public ESTService build()
    {
        return new ESTService(
            server,
            clientProvider);
    }

}



