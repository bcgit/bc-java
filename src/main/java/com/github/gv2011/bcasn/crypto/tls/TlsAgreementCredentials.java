package com.github.gv2011.bcasn.crypto.tls;

import java.io.IOException;

import com.github.gv2011.bcasn.crypto.params.AsymmetricKeyParameter;

public interface TlsAgreementCredentials
    extends TlsCredentials
{
    byte[] generateAgreement(AsymmetricKeyParameter peerPublicKey)
        throws IOException;
}
