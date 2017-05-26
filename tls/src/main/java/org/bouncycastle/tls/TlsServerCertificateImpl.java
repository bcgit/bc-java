package org.bouncycastle.tls;

class TlsServerCertificateImpl
    implements TlsServerCertificate
{
    protected Certificate certificate;
    protected CertificateStatus certificateStatus;

    TlsServerCertificateImpl(Certificate certificate, CertificateStatus certificateStatus)
    {
        this.certificate = certificate;
        this.certificateStatus = certificateStatus;
    }

    public Certificate getCertificate()
    {
        return certificate;
    }

    public CertificateStatus getCertificateStatus()
    {
        return certificateStatus;
    }
}
