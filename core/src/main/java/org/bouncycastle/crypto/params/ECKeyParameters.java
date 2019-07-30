package org.bouncycastle.crypto.params;

public class ECKeyParameters
    extends AsymmetricKeyParameter
{
    private final ECDomainParameters parameters;

    protected ECKeyParameters(
        boolean             isPrivate,
        ECDomainParameters  parameters)
    {
        super(isPrivate);

        if (null == parameters)
        {
            throw new NullPointerException("'parameters' cannot be null");
        }

        this.parameters = parameters;
    }

    public ECDomainParameters getParameters()
    {
        return parameters;
    }
}
