package org.bouncycastle.cert.crmf;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.crmf.EncryptedKey;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSEnvelopedData;

public class CertificateResponseBuilder
{
    private CertifiedKeyPair certKeyPair;
    private ASN1Integer certReqId;
    private PKIStatusInfo statusInfo;
    private DEROctetString rspInfo;

    public CertificateResponseBuilder(ASN1Integer certReqId, PKIStatusInfo statusInfo)
    {
        this.certReqId = certReqId;
        this.statusInfo = statusInfo;
    }

    public CertificateResponseBuilder withCertificate(X509CertificateHolder certificate)
    {
        this.certKeyPair = new CertifiedKeyPair(
            new CertOrEncCert(new CMPCertificate(certificate.toASN1Structure())));

        return this;
    }

    public CertificateResponseBuilder withCertificate(CMSEnvelopedData encryptedCertificate)
    {
        this.certKeyPair = new CertifiedKeyPair(
            new CertOrEncCert(
                new EncryptedKey(EnvelopedData.getInstance(encryptedCertificate.toASN1Structure().getContent()))));

        return this;
    }

    public CertificateResponseBuilder withResponseInfo(byte[] responseInfo)
    {
        this.rspInfo = new DEROctetString(responseInfo);

        return this;
    }

    public CertificateResponse build()
    {
        return new CertificateResponse(new CertResponse(certReqId, statusInfo, certKeyPair, rspInfo));
    }
}
