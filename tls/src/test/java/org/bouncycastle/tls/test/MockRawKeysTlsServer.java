package org.bouncycastle.tls.test;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateEntry;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.CertificateType;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ClientCertificateType;
import org.bouncycastle.tls.DefaultTlsServer;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsCredentialedSigner;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsRawKeyCertificate;

import junit.framework.TestCase;

class MockRawKeysTlsServer extends DefaultTlsServer
{
    private short serverCertType;
    private short clientCertType;
    private short[] allowedClientCertTypes;
    private Ed25519PrivateKeyParameters privateKey;
    private ProtocolVersion tlsVersion;
    private TlsCredentialedSigner credentials;

    Hashtable receivedClientExtensions;

    MockRawKeysTlsServer(short serverCertType, short clientCertType, short[] allowedClientCertTypes,
        Ed25519PrivateKeyParameters privateKey, ProtocolVersion tlsVersion) throws Exception
    {
        super(new BcTlsCrypto());

        this.serverCertType = serverCertType;
        this.clientCertType = clientCertType;
        this.allowedClientCertTypes = allowedClientCertTypes;
        this.privateKey = privateKey;
        this.tlsVersion = tlsVersion;
    }

    public TlsCredentials getCredentials() throws IOException
    {
        /*
         * TODO[tls13] Should really be finding the first client-supported signature scheme that the
         * server also supports and has credentials for.
         */
        if (TlsUtils.isTLSv13(context))
        {
            return getECDSASignerCredentials();
        }

        return super.getCredentials();
    }

    protected ProtocolVersion[] getSupportedVersions()
    {
        return new ProtocolVersion[]{ tlsVersion };
    }

    protected int[] getSupportedCipherSuites()
    {
        return TlsUtils.isTLSv13(tlsVersion)
            ?   new int[]{ CipherSuite.TLS_AES_128_GCM_SHA256 }
            :   new int[]{ CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 };
    }

    public void processClientExtensions(Hashtable clientExtensions) throws IOException
    {
        this.receivedClientExtensions = clientExtensions;

        super.processClientExtensions(clientExtensions);
    }

    protected TlsCredentialedSigner getECDSASignerCredentials() throws IOException
    {
        if (credentials == null)
        {
            BcTlsCrypto crypto = (BcTlsCrypto)getCrypto();

            switch (serverCertType)
            {
            case CertificateType.X509:
                credentials = TlsTestUtils.loadSignerCredentials(context,
                    context.getSecurityParametersHandshake().getClientSigAlgs(), SignatureAlgorithm.ed25519,
                    "x509-client-ed25519.pem", "x509-client-key-ed25519.pem");
                break;
            case CertificateType.RawPublicKey:
                TlsCertificate rawKeyCert = new BcTlsRawKeyCertificate(crypto,
                    SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(privateKey.generatePublicKey()));
                Certificate cert = new Certificate(CertificateType.RawPublicKey,
                    TlsUtils.isTLSv13(context) ? TlsUtils.EMPTY_BYTES : null,
                    new CertificateEntry[]{ new CertificateEntry(rawKeyCert, null) });
                credentials = new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(context),
                    crypto, privateKey, cert, SignatureAndHashAlgorithm.ed25519);
                break;
            default:
                throw new IllegalArgumentException("Only supports X509 and raw keys");
            }
        }

        return credentials;
    }

    protected short[] getAllowedClientCertificateTypes()
    {
        return allowedClientCertTypes;
    }

    protected boolean allowCertificateStatus()
    {
        return serverCertType == CertificateType.RawPublicKey ? false : super.allowCertificateStatus();
    }

    protected boolean allowMultiCertStatus()
    {
        return serverCertType == CertificateType.RawPublicKey ? false : super.allowMultiCertStatus();
    }

    public CertificateRequest getCertificateRequest() throws IOException
    {
        if (clientCertType < 0)
        {
            return null;
        }

        short[] certificateTypes = new short[]{ ClientCertificateType.ecdsa_sign };

        Vector serverSigAlgs = null;
        if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(context.getServerVersion()))
        {
            serverSigAlgs = TlsUtils.getDefaultSupportedSignatureAlgorithms(context);
        }

        return TlsUtils.isTLSv13(tlsVersion)
            ?   new CertificateRequest(TlsUtils.EMPTY_BYTES, serverSigAlgs, null, null)
            :   new CertificateRequest(certificateTypes, serverSigAlgs, null);
    }

    public void notifyClientCertificate(Certificate clientCertificate) throws IOException
    {
        TestCase.assertEquals("client certificate is the wrong type", clientCertType, clientCertificate.getCertificateType());
    }
}
