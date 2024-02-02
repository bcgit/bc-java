package org.bouncycastle.cert.ocsp;

import java.util.Date;

import org.bouncycastle.asn1.ocsp.ResponseData;
import org.bouncycastle.asn1.x509.Extensions;

/**
 * OCSP RFC 2560, RFC 6960
 * <pre>
 * ResponseData ::= SEQUENCE {
 *     version              [0] EXPLICIT Version DEFAULT v1,
 *     responderID              ResponderID,
 *     producedAt               GeneralizedTime,
 *     responses                SEQUENCE OF SingleResponse,
 *     responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
 * </pre>
 */
public class RespData
{
    private ResponseData    data;

    public RespData(
        ResponseData    data)
    {
        this.data = data;
    }

    public int getVersion()
    {
        return data.getVersion().intValueExact() + 1;
    }

    public RespID getResponderId()
    {
        return new RespID(data.getResponderID());
    }

    public Date getProducedAt()
    {
        return OCSPUtils.extractDate(data.getProducedAt());
    }

    public SingleResp[] getResponses()
    {
        return OCSPUtils.getResponses(data);
    }

    public Extensions getResponseExtensions()
    {
        return data.getResponseExtensions();
    }
}
