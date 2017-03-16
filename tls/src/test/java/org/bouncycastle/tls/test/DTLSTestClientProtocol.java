package org.bouncycastle.tls.test;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.tls.DTLSClientProtocol;
import org.bouncycastle.tls.DigitallySigned;

class DTLSTestClientProtocol extends DTLSClientProtocol
{
    protected final TlsTestConfig config;

    public DTLSTestClientProtocol(SecureRandom secureRandom, TlsTestConfig config)
    {
        super(secureRandom);

        this.config = config;
    }

    protected byte[] generateCertificateVerify(ClientHandshakeState state, DigitallySigned certificateVerify)
        throws IOException
    {
        if (certificateVerify.getAlgorithm() != null && config.clientAuthSigAlgClaimed != null)
        {
            certificateVerify = new DigitallySigned(config.clientAuthSigAlgClaimed, certificateVerify.getSignature());
        }

        return super.generateCertificateVerify(state, certificateVerify);
    }
}
