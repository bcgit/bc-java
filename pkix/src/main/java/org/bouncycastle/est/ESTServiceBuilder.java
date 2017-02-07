package org.bouncycastle.est;


/**
 * Build a RFC7030 client.
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



