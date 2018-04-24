package org.bouncycastle.est;


/**
 * Build an RFC7030 (EST) service.
 */
public class ESTServiceBuilder
{
    protected final String server;
    protected ESTClientProvider clientProvider;
    protected String label;

    /**
     * With scheme and host..
     *
     * @param server The authority name, eg estserver.co.au
     */
    public ESTServiceBuilder(String server)
    {
        this.server = server;
    }

    /**
     * Set the label as per https://tools.ietf.org/html/rfc7030#section-3.2.2
     *
     * @param label The label.
     * @return this builder.
     */
    public ESTServiceBuilder withLabel(String label)
    {
        this.label = label;
        return this;
    }

    /**
     * Set the client provider.
     *
     * @param clientProvider The client provider.
     * @return
     */
    public ESTServiceBuilder withClientProvider(ESTClientProvider clientProvider)
    {
        this.clientProvider = clientProvider;
        return this;
    }

    /**
     * Build the service.
     *
     * @return an ESTService.
     */
    public ESTService build()
    {
        return new ESTService(
            server,
            label,
            clientProvider);
    }

}



