package org.bouncycastle.jsse.provider;

class JsseSessionParameters
{
    private final String identificationProtocol;

    JsseSessionParameters(String identificationProtocol)
    {
        this.identificationProtocol = identificationProtocol;
    }

    public String getIdentificationProtocol()
    {
        return identificationProtocol;
    }
}
