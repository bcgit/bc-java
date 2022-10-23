package org.bouncycastle.cert.crmf;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;

public class CertificateResponse
{
    private final CertResponse certResponse;

    public CertificateResponse(CertResponse certResponse)
    {

        this.certResponse = certResponse;
    }

    public boolean hasEncryptecCertificate()
    {
        return certResponse.getCertifiedKeyPair().getCertOrEncCert().hasEncryptedCertificate();
    }

    public CMSEnvelopedData getEncryptedCertificate()
        throws CMSException
    {
        CertifiedKeyPair receivedKeyPair = certResponse.getCertifiedKeyPair();

        return new CMSEnvelopedData(
            new ContentInfo(PKCSObjectIdentifiers.envelopedData, receivedKeyPair.getCertOrEncCert().getEncryptedCert().getValue()));
    }

    public CMPCertificate getCertificate()
        throws CMSException
    {
        return certResponse.getCertifiedKeyPair().getCertOrEncCert().getCertificate();
    }

    public CertResponse toASN1Structure()
    {
        return certResponse;
    }
}
