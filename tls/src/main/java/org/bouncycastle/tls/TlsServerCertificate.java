package org.bouncycastle.tls;

public interface TlsServerCertificate
{
    Certificate getCertificate();

    CertificateStatus getCertificateStatus();
}
