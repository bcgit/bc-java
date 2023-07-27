package org.bouncycastle.cert.crmf;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Builder for a CertificateRepMessage.
 */
public class CertificateRepMessageBuilder
{
    private final List<CertResponse> responses = new ArrayList<CertResponse>();
    private final CMPCertificate[] caCerts;

    /**
     * Base constructor which can accept 0 or more certificates representing the CA plus its chain.
     *
     * @param caCerts the CA public key and it's support certificates (optional)
     */
    public CertificateRepMessageBuilder(X509CertificateHolder... caCerts)
    {
        this.caCerts = new CMPCertificate[caCerts.length];

        for (int i = 0; i != caCerts.length; i++)
        {
            this.caCerts[i] = new CMPCertificate(caCerts[i].toASN1Structure());
        }
    }
    public CertificateRepMessageBuilder addCertificateResponse(CertificateResponse response)
    {
        responses.add(response.toASN1Structure());

        return this;
    }

    public CertificateRepMessage build()
    {
        CertRepMessage repMessage;
        if (caCerts.length != 0)
        {
            repMessage = new CertRepMessage(caCerts, (CertResponse[])responses.toArray(new CertResponse[0]));
        }
        else
        {
            // older versions of CertRepMessage need null if no caCerts.
            repMessage = new CertRepMessage(null, (CertResponse[])responses.toArray(new CertResponse[0]));
        }

        responses.clear();

        return new CertificateRepMessage(repMessage);
    }
}
