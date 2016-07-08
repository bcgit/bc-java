package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.crypto.TlsSecret;

public interface TlsAgreementCredentials
    extends TlsCredentials
{
    TlsSecret generateAgreement(AsymmetricKeyParameter peerPublicKey) throws IOException;
}
