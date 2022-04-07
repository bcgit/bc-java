package org.bouncycastle.tls.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Vector;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateEntry;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.CertificateStatusRequest;
import org.bouncycastle.tls.CertificateType;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsCredentialedSigner;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsRawKeyCertificate;

class MockRawKeysTlsClient extends DefaultTlsClient
{

    private short serverCertType;
    private short clientCertType;
    private short[] offerServerCertTypes;
    private short[] offerClientCertTypes;
    private Ed25519PrivateKeyParameters privateKey;
    private ProtocolVersion tlsVersion;
    private TlsCredentialedSigner credentials;

    MockRawKeysTlsClient(short serverCertType, short clientCertType,
            short[] offerServerCertTypes, short[] offerClientCertTypes,
            Ed25519PrivateKeyParameters privateKey,
            ProtocolVersion tlsVersion) throws Exception
    {
        super(new BcTlsCrypto(new SecureRandom()));
        this.serverCertType = serverCertType;
        this.clientCertType = clientCertType;
        this.offerServerCertTypes = offerServerCertTypes;
        this.offerClientCertTypes = offerClientCertTypes;
        this.privateKey = privateKey;
        this.tlsVersion = tlsVersion;
    }

    @Override
    protected ProtocolVersion[] getSupportedVersions()
    {
        return new ProtocolVersion[] {tlsVersion};
    }

    @Override
    protected int[] getSupportedCipherSuites()
    {
        return ProtocolVersion.TLSv13.equals(tlsVersion) ?
                new int[] {CipherSuite.TLS_AES_128_GCM_SHA256} :
                new int[] {CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256};
    }

    @Override
    protected short[] getAllowedClientCertificateTypes()
    {
        return offerClientCertTypes;
    }

    @Override
    protected short[] getAllowedServerCertificateTypes()
    {
        return offerServerCertTypes;
    }

    @Override
    protected CertificateStatusRequest getCertificateStatusRequest()
    {
        return serverCertType == CertificateType.RawPublicKey ? null : super.getCertificateStatusRequest();
    }

    @Override
    protected Vector getMultiCertStatusRequest()
    {
        return serverCertType == CertificateType.RawPublicKey ? null : super.getMultiCertStatusRequest();
    }

    @Override
    public TlsAuthentication getAuthentication() throws IOException
    {
        return new TlsAuthentication()
        {
            @Override
            public void notifyServerCertificate(TlsServerCertificate serverCertificate) throws IOException
            {
                assertEquals("wrong certificate type from server", serverCertType, serverCertificate.getCertificate().getCertificateType());
            }

            @Override
            public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException
            {
                if (clientCertType < 0)
                {
                    fail("should not have received a certificate request");
                }

                assertEquals("wrong certificate type in request", clientCertType, certificateRequest.getCertificateType());

                if (credentials == null)
                {
                    switch (clientCertType)
                    {
                    case CertificateType.X509:
                        credentials = TlsTestUtils.loadSignerCredentials(context, certificateRequest.getSupportedSignatureAlgorithms(),
                                SignatureAlgorithm.ed25519, "x509-client-ed25519.pem", "x509-client-key-ed25519.pem");
                        break;
                    case CertificateType.RawPublicKey:
                        TlsCertificate rawKeyCert = new BcTlsRawKeyCertificate(
                                getCrypto(),
                                SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(privateKey.generatePublicKey()));
                        Certificate cert = new Certificate(
                                CertificateType.RawPublicKey,
                                TlsUtils.isTLSv13(context) ? TlsUtils.EMPTY_BYTES : null,
                                new CertificateEntry[] {new CertificateEntry(rawKeyCert, null)});
                        credentials = new BcDefaultTlsCredentialedSigner(
                                new TlsCryptoParameters(context),
                                getCrypto(),
                                privateKey,
                                cert,
                                SignatureAndHashAlgorithm.ed25519);
                        break;
                    default:
                        throw new IllegalArgumentException("Only supports X509 and raw keys");
                    }
                }

                return credentials;
            }
        };
    }

    @Override
    public BcTlsCrypto getCrypto()
    {
        return (BcTlsCrypto) super.getCrypto();
    }

}
