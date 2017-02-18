package org.bouncycastle.est;

/**
 * CSRRequestResponse
 */
public class CSRRequestResponse
{
    private final CSRAttributesResponse attributesResponse;
    private final Source source;

    public CSRRequestResponse(CSRAttributesResponse attributesResponse, Source session)
    {
        this.attributesResponse = attributesResponse;
        this.source = session;
    }

    public CSRAttributesResponse getAttributesResponse()
    {
        return attributesResponse;
    }

    public Object getSession()
    {
        return source.getSession();
    }

    public Source getSource()
    {
        return source;
    }
}
