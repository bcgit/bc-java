package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.TlsClientProtocol;

class TlsTestClientProtocol extends TlsClientProtocol
{
    protected final TlsTestConfig config;

    TlsTestClientProtocol(InputStream input, OutputStream output, TlsTestConfig config)
    {
        super(input, output);

        this.config = config;
    }

    protected void send13CertificateVerifyMessage(DigitallySigned certificateVerify) throws IOException
    {
        if (config.clientAuthSigAlgClaimed != null)
        {
            certificateVerify = new DigitallySigned(config.clientAuthSigAlgClaimed, certificateVerify.getSignature());
        }

        super.send13CertificateVerifyMessage(certificateVerify);
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
