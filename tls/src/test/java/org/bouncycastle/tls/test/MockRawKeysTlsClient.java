package org.bouncycastle.tls.test;

import java.io.IOException;
import java.util.Vector;

import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.CertificateStatusRequest;
import org.bouncycastle.tls.CertificateType;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsCredentialedSigner;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCrypto;

import junit.framework.TestCase;

class MockRawKeysTlsClient
    extends DefaultTlsClient
{
    private short serverCertType;
    private short clientCertType;
    private short[] offerServerCertTypes;
    private short[] offerClientCertTypes;
    private ProtocolVersion tlsVersion;
    private TlsCredentialedSigner credentials;

    MockRawKeysTlsClient(short serverCertType, short clientCertType, short[] offerServerCertTypes,
        short[] offerClientCertTypes, TlsCrypto crypto, ProtocolVersion tlsVersion)
        throws Exception
    {
        super(crypto);

        this.serverCertType = serverCertType;
        this.clientCertType = clientCertType;
        this.offerServerCertTypes = offerServerCertTypes;
        this.offerClientCertTypes = offerClientCertTypes;
        this.tlsVersion = tlsVersion;
    }

    protected ProtocolVersion[] getSupportedVersions()
    {
        return new ProtocolVersion[]{tlsVersion};
    }

    protected int[] getSupportedCipherSuites()
    {
        return TlsUtils.isTLSv13(tlsVersion)
            ?   new int[]{ CipherSuite.TLS_AES_128_GCM_SHA256 }
            :   new int[]{ CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 };
    }

    protected short[] getAllowedClientCertificateTypes()
    {
        return offerClientCertTypes;
    }

    protected short[] getAllowedServerCertificateTypes()
    {
        return offerServerCertTypes;
    }

    protected CertificateStatusRequest getCertificateStatusRequest()
    {
        return serverCertType == CertificateType.RawPublicKey ? null : super.getCertificateStatusRequest();
    }

    protected Vector getMultiCertStatusRequest()
    {
        return serverCertType == CertificateType.RawPublicKey ? null : super.getMultiCertStatusRequest();
    }

    public TlsAuthentication getAuthentication() throws IOException
    {
        return new TlsAuthentication()
        {
            public void notifyServerCertificate(TlsServerCertificate serverCertificate) throws IOException
            {
                TestCase.assertEquals("wrong certificate type from server", serverCertType, serverCertificate.getCertificate().getCertificateType());
            }

            public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException
            {
                if (clientCertType < 0)
                {
                    TestCase.fail("should not have received a certificate request");
                }

                TestCase.assertEquals("wrong certificate type in request", clientCertType, context.getSecurityParametersHandshake().getClientCertificateType());

                if (credentials == null)
                {
                    switch (clientCertType)
                    {
                    case CertificateType.X509:
                        credentials = TlsTestUtils.loadSignerCredentials(context, certificateRequest.getSupportedSignatureAlgorithms(),
                                SignatureAlgorithm.ed25519, "x509-client-ed25519.pem", "x509-client-key-ed25519.pem");
                        break;
                    case CertificateType.RawPublicKey:
                        credentials = TlsTestUtils.createRawKeyEd25519Credentials(context);
                        break;
                    default:
                        throw new IllegalArgumentException("Only supports X509 and raw keys");
                    }
                }

                return credentials;
            }
        };
    }
}
