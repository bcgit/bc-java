package org.bouncycastle.cert.crmf;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.cert.X509CertificateHolder;

public class CertificateRepMessage
{
    private final CertResponse[] resps;
    private final CMPCertificate[] caCerts;

    public CertificateRepMessage(CertRepMessage repMessage)
    {
        resps = repMessage.getResponse();
        caCerts = repMessage.getCaPubs();
    }

    public static CertificateRepMessage fromPKIBody(PKIBody pkiBody)
    {
        if (!isCertificateRepMessage(pkiBody.getType()))
        {
            throw new IllegalArgumentException("content of PKIBody wrong type: " + pkiBody.getType());
        }

        return new CertificateRepMessage(CertRepMessage.getInstance(pkiBody.getContent()));
    }

    public static boolean isCertificateRepMessage(int bodyType)
    {
        switch (bodyType)
        {
        case PKIBody.TYPE_INIT_REP:
        case PKIBody.TYPE_CERT_REP:
        case PKIBody.TYPE_KEY_UPDATE_REP:
        case PKIBody.TYPE_CROSS_CERT_REP:
            return true;
        default:
            return false;
        }
    }

    public CertificateResponse[] getResponses()
    {
        CertificateResponse[] responses = new CertificateResponse[resps.length];
        for (int i = 0; i != responses.length; i++)
        {
            responses[i] = new CertificateResponse(resps[i]);
        }

        return responses;
    }

    public X509CertificateHolder[] getX509Certificates()
    {
        List<X509CertificateHolder> certs = new ArrayList<X509CertificateHolder>();

        for (int i = 0; i != caCerts.length; i++)
        {
            if (caCerts[i].isX509v3PKCert())
            {
                certs.add(new X509CertificateHolder(caCerts[i].getX509v3PKCert()));
            }
        }

        return (X509CertificateHolder[])certs.toArray(new X509CertificateHolder[0]);
    }

    /**
     * Checks if the message only contains X.509 public key certificates
     * or if the X.509 public key certificates array is null.
     *
     * @return true if the message only contains X.509 public key certificates or the array is null, false otherwise.
     */
    public boolean isOnlyX509PKCertificates()
    {
        boolean isOnlyX509 = true;

        if (caCerts != null)
        {
            for (int i = 0; i != caCerts.length; i++)
            {
                isOnlyX509 &= caCerts[i].isX509v3PKCert();
            }
        }

        return isOnlyX509;
    }

    /**
     * Returns the array of CMP certificates, including non-X509 PK certificates if present.
     * <p>
     * Note: If the array contains non-X509 PK certificates, they will be included in the result.
     *
     * @return An array of CMPCertificate objects or null if the array is empty.
     */
    public CMPCertificate[] getCMPCertificates()
    {
        if (caCerts != null)
        {
            CMPCertificate[] certs = new CMPCertificate[caCerts.length];

            System.arraycopy(caCerts, 0, certs, 0, certs.length);

            return certs;
        }
        return null;
    }

    public CertRepMessage toASN1Structure()
    {
        return new CertRepMessage(caCerts, resps);
    }
}
