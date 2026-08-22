package org.bouncycastle.tls;

class TlsServerCertificateImpl
    implements TlsServerCertificate
{
    protected Certificate certificate;
    protected CertificateStatus certificateStatus;
    protected CertificateStatus[] certificateStatuses;

    /**
     * @param certificateStatus   what {@link #getCertificateStatus()} answers with: up to TLS 1.2
     *                            the "certificate_status" message as it arrived, which is the
     *                            ocsp_multi list itself where the client asked with
     *                            "status_request_v2"; from TLS 1.3 the first entry's staple.
     * @param certificateStatuses one entry per certificate of <code>certificate</code>, null where
     *                            that certificate was left unstapled.
     */
    TlsServerCertificateImpl(Certificate certificate, CertificateStatus certificateStatus,
        CertificateStatus[] certificateStatuses)
    {
        this.certificate = certificate;
        this.certificateStatus = certificateStatus;
        this.certificateStatuses = certificateStatuses;
    }

    public Certificate getCertificate()
    {
        return certificate;
    }

    public CertificateStatus getCertificateStatus()
    {
        return certificateStatus;
    }

    public CertificateStatus getCertificateStatusAt(int index)
    {
        return certificateStatuses[index];
    }
}
