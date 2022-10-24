package org.bouncycastle.cert.cmp;

import org.bouncycastle.asn1.cmp.CertConfirmContent;
import org.bouncycastle.asn1.cmp.CertStatus;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;

/**
 * Carrier class for a {@link CertConfirmContent} message.
 */
public class CertificateConfirmationContent
{
    private DigestAlgorithmIdentifierFinder digestAlgFinder;
    private CertConfirmContent content;

    public CertificateConfirmationContent(CertConfirmContent content)
    {
        this(content, new DefaultDigestAlgorithmIdentifierFinder());
    }

    public CertificateConfirmationContent(CertConfirmContent content, DigestAlgorithmIdentifierFinder digestAlgFinder)
    {
        this.digestAlgFinder = digestAlgFinder;
        this.content = content;
    }

    public static CertificateConfirmationContent fromPKIBody(PKIBody pkiBody)
    {
        return fromPKIBody(pkiBody, new DefaultDigestAlgorithmIdentifierFinder());
    }

    public static CertificateConfirmationContent fromPKIBody(PKIBody pkiBody, DigestAlgorithmIdentifierFinder digestAlgFinder)
    {
        if (!isCertificateConfirmationContent(pkiBody.getType()))
        {
            throw new IllegalArgumentException("content of PKIBody wrong type: " + pkiBody.getType());
        }

        return new CertificateConfirmationContent(CertConfirmContent.getInstance(pkiBody.getContent()), digestAlgFinder);
    }

    public static boolean isCertificateConfirmationContent(int bodyType)
    {
        switch (bodyType)
        {
        case PKIBody.TYPE_CERT_CONFIRM:
            return true;
        default:
            return false;
        }
    }

    public CertConfirmContent toASN1Structure()
    {
        return content;
    }

    public CertificateStatus[] getStatusMessages()
    {
        CertStatus[] statusArray = content.toCertStatusArray();
        CertificateStatus[] ret = new CertificateStatus[statusArray.length];

        for (int i = 0; i != ret.length; i++)
        {
            ret[i] = new CertificateStatus(digestAlgFinder, statusArray[i]);
        }

        return ret;
    }
}
