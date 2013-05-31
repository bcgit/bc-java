package org.bouncycastle.cert.cmp;

import org.bouncycastle.asn1.cmp.CertConfirmContent;
import org.bouncycastle.asn1.cmp.CertStatus;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;

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
