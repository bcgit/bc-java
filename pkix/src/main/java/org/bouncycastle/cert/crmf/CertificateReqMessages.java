package org.bouncycastle.cert.crmf;

import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;

public class CertificateReqMessages
{
    private final CertReqMsg[] reqs;

    public CertificateReqMessages(CertReqMessages certReqMessages)
    {
        reqs = certReqMessages.toCertReqMsgArray();
    }

    public static CertificateReqMessages fromPKIBody(PKIBody pkiBody)
    {
        if (!isCertificateRequestMessages(pkiBody.getType()))
        {
            throw new IllegalArgumentException("content of PKIBody wrong type: " + pkiBody.getType());
        }

        return new CertificateReqMessages(CertReqMessages.getInstance(pkiBody.getContent()));
    }

    public static boolean isCertificateRequestMessages(int bodyType)
    {
        switch (bodyType)
        {
        case PKIBody.TYPE_INIT_REQ:
        case PKIBody.TYPE_CERT_REQ:
        case PKIBody.TYPE_KEY_UPDATE_REQ:
        case PKIBody.TYPE_KEY_RECOVERY_REQ:
        case PKIBody.TYPE_CROSS_CERT_REQ:
            return true;
        default:
            return false;
        }
    }

    public CertificateRequestMessage[] getRequests()
    {
        CertificateRequestMessage[] requestMessages = new CertificateRequestMessage[reqs.length];
        for (int i = 0; i != requestMessages.length; i++)
        {
            requestMessages[i] = new CertificateRequestMessage(reqs[i]);
        }

        return requestMessages;
    }

    public CertReqMessages toASN1Structure()
    {
        return new CertReqMessages(reqs);
    }
}
