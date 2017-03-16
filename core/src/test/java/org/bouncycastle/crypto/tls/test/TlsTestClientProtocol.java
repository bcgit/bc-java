package org.bouncycastle.crypto.tls.test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

import org.bouncycastle.crypto.tls.DigitallySigned;
import org.bouncycastle.crypto.tls.TlsClientProtocol;

class TlsTestClientProtocol extends TlsClientProtocol
{
    protected final TlsTestConfig config;

    public TlsTestClientProtocol(InputStream input, OutputStream output, SecureRandom secureRandom, TlsTestConfig config)
    {
        super(input, output, secureRandom);

        this.config = config;
    }

    protected void sendCertificateVerifyMessage(DigitallySigned certificateVerify) throws IOException
    {
        if (certificateVerify.getAlgorithm() != null && config.clientAuthSigAlgClaimed != null)
        {
            certificateVerify = new DigitallySigned(config.clientAuthSigAlgClaimed, certificateVerify.getSignature());
        }

        super.sendCertificateVerifyMessage(certificateVerify);
    }
}
