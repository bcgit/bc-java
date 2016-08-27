package org.bouncycastle.tls.crypto;

import java.io.IOException;

import org.bouncycastle.tls.TlsCredentials;

public interface TlsAgreementCredentials
    extends TlsCredentials
{
    TlsSecret generateAgreement(TlsCertificate peerCertificate) throws IOException;
}
