package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsSecret;

public interface TlsAgreementCredentials
    extends TlsCredentials
{
    TlsSecret generateAgreement(TlsCertificate peerCertificate) throws IOException;
}
