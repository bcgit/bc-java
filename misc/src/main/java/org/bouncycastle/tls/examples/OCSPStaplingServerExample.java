package org.bouncycastle.tls.examples;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Vector;

import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.CertificateStatus;
import org.bouncycastle.tls.CertificateStatusRequestItemV2;
import org.bouncycastle.tls.CertificateStatusType;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.DefaultTlsServer;
import org.bouncycastle.tls.OCSPStatusRequest;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsCredentialedSigner;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

/**
 * Example: server-side OCSP stapling with the lightweight
 * {@code org.bouncycastle.tls} API (github issue #1157).
 * <p>
 * A TLS server staples a certificate status by overriding a single method,
 * {@link org.bouncycastle.tls.TlsServer#getCertificateStatus()}. The protocol
 * plumbing around it is already in place: {@code AbstractTlsServer} notes the
 * client's "status_request" (<a href="https://www.rfc-editor.org/rfc/rfc6066#section-8">RFC
 * 6066 sec. 8</a>) and "status_request_v2"
 * (<a href="https://www.rfc-editor.org/rfc/rfc6961#section-2.2">RFC 6961 sec. 2.2</a>)
 * extensions, echoes the agreed one back in the ServerHello, and
 * {@code TlsServerProtocol} / {@code DTLSServerProtocol} then send whatever this method
 * returns as a "certificate_status" handshake message. The server never fetches
 * anything itself &mdash; where the response comes from (a cached responder fetch, a file
 * refreshed out of band, an in-process responder as here) is entirely the application's
 * choice, which is the point of the callback.
 * <p>
 * Two things the callback has to get right up to (D)TLS 1.2, both illustrated below
 * (TLS 1.3 reads the shape differently &mdash; see <b>Scope</b>):
 * <ul>
 * <li>Which <i>shape</i> of response to return. Ask
 * {@code context.getSecurityParametersHandshake().getStatusRequestVersion()}: 1 means the
 * server echoed "status_request" and the client expects a single
 * {@link CertificateStatusType#ocsp} response for the end-entity certificate; 2 means it
 * echoed "status_request_v2" and the client expects an
 * {@link CertificateStatusType#ocsp_multi} list, one entry per certificate in the chain,
 * in chain order, with a null entry where no response is available. Returning the wrong
 * one is a fatal alert at the client.</li>
 * <li>That "status_request_v2" is opt-in. {@code allowCertificateStatus()} defaults to
 * true, but {@code allowMultiCertStatus()} defaults to <b>false</b>, so a server that
 * wants to answer RFC 6961 clients must override it.</li>
 * </ul>
 * <p>
 * <b>Scope:</b> this example negotiates TLS 1.2, where the response travels as one
 * "certificate_status" handshake message covering the whole chain. That message does not
 * exist in TLS 1.3, which instead carries each response in a "status_request" extension of
 * the CertificateEntry holding the certificate it answers for
 * (<a href="https://www.rfc-editor.org/rfc/rfc8446#section-4.4.2.1">RFC 8446 sec.
 * 4.4.2.1</a>). The callback is the same one either way &mdash; {@code TlsServerProtocol}
 * distributes what it returns across those entries &mdash; so the only thing that changes
 * for an implementation is how the shape is chosen: the status request version is always 1
 * in TLS 1.3 ("status_request_v2" is left out of it by RFC 8446 sec. 4.2.1), so a server
 * with responses for the intermediates as well returns the
 * {@link CertificateStatusType#ocsp_multi} shape there regardless, answering positionally
 * against the chain. Note also that this is the low-level TLS API; the BCJSSE provider
 * fetches and staples responses of its own accord, behind the
 * {@code jdk.tls.server.enableStatusRequestExtension} system property.
 */
public class OCSPStaplingServerExample
{
    private static final String SIG_ALG = "SHA256withRSA";

    public static void main(String[] args)
        throws Exception
    {
        if (null == Security.getProvider(BouncyCastleProvider.PROVIDER_NAME))
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        SecureRandom random = new SecureRandom();

        /*
         * A two-certificate PKI: a self-signed CA, and the server certificate it issued. The CA
         * key doubles as the OCSP responder key here, which is the "responder is the issuer" case
         * of RFC 6960 sec. 4.2.2.2; a real deployment more often delegates to a separate
         * id-kp-OCSPSigning certificate.
         */
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        kpGen.initialize(2048, random);

        KeyPair caKeyPair = kpGen.generateKeyPair();
        KeyPair serverKeyPair = kpGen.generateKeyPair();

        X509Certificate caCert = createCACertificate(caKeyPair);
        X509Certificate serverCert = createServerCertificate(serverKeyPair.getPublic(), caKeyPair, caCert);

        /*
         * The response the server will staple. In production this is whatever the application last
         * obtained from the CA's responder, kept fresh against its nextUpdate.
         */
        OCSPResponse ocspResponse = createOCSPResponse(caKeyPair, caCert, serverCert);

        /*
         * Two handshakes against the same server, one per extension, so both branches of
         * getCertificateStatus() below get exercised.
         */
        System.out.println("=== client offering RFC 6066 \"status_request\" only ===");
        runHandshake(random, caCert, serverCert, serverKeyPair.getPrivate(), ocspResponse, false);

        System.out.println("=== client also offering RFC 6961 \"status_request_v2\" ===");
        runHandshake(random, caCert, serverCert, serverKeyPair.getPrivate(), ocspResponse, true);
    }

    private static void runHandshake(SecureRandom random, X509Certificate caCert, X509Certificate serverCert,
        PrivateKey serverPrivateKey, OCSPResponse ocspResponse, boolean offerStatusRequestV2)
        throws Exception
    {
        // Run a handshake between the two peers over a pair of pipes.
        PipedInputStream clientRead = new PipedInputStream(1 << 16);
        PipedInputStream serverRead = new PipedInputStream(1 << 16);
        OutputStream clientWrite = new PipedOutputStream(serverRead);
        OutputStream serverWrite = new PipedOutputStream(clientRead);

        ServerTask serverTask = new ServerTask(serverRead, serverWrite, serverCert, caCert, serverPrivateKey,
            ocspResponse);

        Thread serverThread = new Thread(serverTask);
        serverThread.start();

        JcaTlsCrypto crypto = new JcaTlsCryptoProvider()
            .setProvider(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME))
            .create(random);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        clientProtocol.connect(new StaplingTlsClient(crypto, caCert, offerStatusRequestV2));

        // Exchange a little application data, to show the connection is usable; the server echoes.
        byte[] data = Strings.toByteArray("stapling example");

        OutputStream appOut = clientProtocol.getOutputStream();
        appOut.write(data);

        byte[] echo = new byte[data.length];
        Streams.readFully(clientProtocol.getInputStream(), echo);

        System.out.println("TLS client read back: " + Strings.fromByteArray(echo));

        // Closing the application OutputStream sends close_notify and shuts the connection down.
        appOut.close();

        serverThread.join();

        serverTask.checkFailure();
    }

    /**
     * A server that staples. Everything specific to stapling is in this class.
     */
    static class StaplingTlsServer
        extends DefaultTlsServer
    {
        private final Certificate certificate;
        private final PrivateKey privateKey;
        private final OCSPResponse ocspResponse;

        StaplingTlsServer(JcaTlsCrypto crypto, Certificate certificate, PrivateKey privateKey,
            OCSPResponse ocspResponse)
        {
            super(crypto);

            this.certificate = certificate;
            this.privateKey = privateKey;
            this.ocspResponse = ocspResponse;
        }

        protected ProtocolVersion[] getSupportedVersions()
        {
            /*
             * The "certificate_status" message exists only up to (D)TLS 1.2 - see the class
             * javadoc.
             */
            return ProtocolVersion.TLSv12.only();
        }

        protected boolean allowMultiCertStatus()
        {
            /*
             * Opt in to RFC 6961 "status_request_v2" (the default is false). With this the server
             * will echo "status_request_v2" in preference to "status_request" whenever the client
             * offered both, and getCertificateStatus() below then sees version 2.
             *
             * allowCertificateStatus(), governing plain RFC 6066 "status_request", already
             * defaults to true and so needs no override.
             */
            return true;
        }

        public CertificateStatus getCertificateStatus()
            throws IOException
        {
            /*
             * Only reached when the server echoed one of the two extensions back to the client,
             * i.e. when getStatusRequestVersion() is non-zero. The version says which shape of
             * response the client is prepared to accept.
             */
            int statusRequestVersion = context.getSecurityParametersHandshake().getStatusRequestVersion();

            switch (statusRequestVersion)
            {
            case 2:
            {
                /*
                 * RFC 6961: one entry per certificate in the chain we sent, in the same order. A
                 * null entry encodes as a zero-length response, meaning "none available for this
                 * certificate" - which is what we say for the CA certificate here.
                 */
                Vector ocspResponseList = new Vector();
                ocspResponseList.addElement(ocspResponse);
                for (int i = 1; i < certificate.getLength(); ++i)
                {
                    ocspResponseList.addElement(null);
                }

                System.out.println("TLS server stapling ocsp_multi status for " + certificate.getLength()
                    + " certificate(s)");

                return new CertificateStatus(CertificateStatusType.ocsp_multi, ocspResponseList);
            }
            case 1:
            {
                // RFC 6066: a single response, covering the end-entity certificate.
                System.out.println("TLS server stapling ocsp status for the end-entity certificate");

                return new CertificateStatus(CertificateStatusType.ocsp, ocspResponse);
            }
            default:
                // Not reached; returning null here simply means "no status stapled".
                return null;
            }
        }

        protected TlsCredentialedSigner getRSASignerCredentials()
            throws IOException
        {
            Vector clientSigAlgs = context.getSecurityParametersHandshake().getClientSigAlgs();

            SignatureAndHashAlgorithm sigAlg = TlsUtils.chooseSignatureAndHashAlgorithm(context, clientSigAlgs,
                SignatureAlgorithm.rsa);

            return new JcaDefaultTlsCredentialedSigner(new TlsCryptoParameters(context), (JcaTlsCrypto)getCrypto(),
                privateKey, certificate, sigAlg);
        }

        public CertificateRequest getCertificateRequest()
            throws IOException
        {
            // No client authentication in this example.
            return null;
        }

        public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
        {
            if (AlertLevel.fatal == alertLevel)
            {
                System.err.println("TLS server raised alert: " + AlertLevel.getText(alertLevel) + ", "
                    + AlertDescription.getText(alertDescription));
            }
        }
    }

    /**
     * A client that asks for a stapled status and reports what came back.
     */
    static class StaplingTlsClient
        extends DefaultTlsClient
    {
        private final X509Certificate caCert;
        private final boolean offerStatusRequestV2;

        StaplingTlsClient(JcaTlsCrypto crypto, X509Certificate caCert, boolean offerStatusRequestV2)
        {
            super(crypto);

            this.caCert = caCert;
            this.offerStatusRequestV2 = offerStatusRequestV2;
        }

        protected ProtocolVersion[] getSupportedVersions()
        {
            return ProtocolVersion.TLSv12.only();
        }

        protected Vector getMultiCertStatusRequest()
        {
            /*
             * AbstractTlsClient already offers RFC 6066 "status_request" by default (see
             * getCertificateStatusRequest()); this adds the RFC 6961 "status_request_v2" offer, so
             * the server above can demonstrate both shapes. Offering ocsp_multi ahead of ocsp
             * within the extension is the RFC 6961 sec. 2.2 preference order.
             */
            if (!offerStatusRequestV2)
            {
                return null;
            }

            Vector statusRequestV2 = new Vector();
            statusRequestV2.addElement(new CertificateStatusRequestItemV2(CertificateStatusType.ocsp_multi,
                new OCSPStatusRequest(null, null)));
            statusRequestV2.addElement(new CertificateStatusRequestItemV2(CertificateStatusType.ocsp,
                new OCSPStatusRequest(null, null)));
            return statusRequestV2;
        }

        public TlsAuthentication getAuthentication()
            throws IOException
        {
            return new TlsAuthentication()
            {
                public void notifyServerCertificate(TlsServerCertificate serverCertificate)
                    throws IOException
                {
                    Certificate chain = serverCertificate.getCertificate();
                    if (null == chain || chain.isEmpty())
                    {
                        throw new TlsFatalAlert(AlertDescription.bad_certificate);
                    }

                    /*
                     * A real client validates the chain here (see the pkix CertPathBuilder /
                     * PKIXCertPathReviewer APIs); this example only checks the issuer is the CA it
                     * generated, so the focus stays on the stapled status.
                     */
                    checkIssuedByCA(chain);

                    reportCertificateStatus(chain, serverCertificate.getCertificateStatus());
                }

                public TlsCredentials getClientCredentials(CertificateRequest certificateRequest)
                    throws IOException
                {
                    return null;
                }
            };
        }

        public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
        {
            if (AlertLevel.fatal == alertLevel)
            {
                System.err.println("TLS client raised alert: " + AlertLevel.getText(alertLevel) + ", "
                    + AlertDescription.getText(alertDescription));
            }
        }

        private void checkIssuedByCA(Certificate chain)
            throws IOException
        {
            TlsCertificate eeCert = chain.getCertificateAt(0);

            try
            {
                X509CertificateHolder holder = new X509CertificateHolder(eeCert.getEncoded());

                if (!holder.isSignatureValid(new JcaContentVerifierProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caCert.getPublicKey())))
                {
                    throw new TlsFatalAlert(AlertDescription.bad_certificate);
                }
            }
            catch (TlsFatalAlert e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new TlsFatalAlert(AlertDescription.bad_certificate, e);
            }
        }

        private void reportCertificateStatus(Certificate chain, CertificateStatus certificateStatus)
            throws IOException
        {
            if (null == certificateStatus)
            {
                System.out.println("TLS client received no stapled certificate status");
                return;
            }

            switch (certificateStatus.getStatusType())
            {
            case CertificateStatusType.ocsp:
            {
                System.out.println("TLS client received a stapled ocsp status:");
                printOCSPResponse(chain.getCertificateAt(0), certificateStatus.getOCSPResponse());
                break;
            }
            case CertificateStatusType.ocsp_multi:
            {
                Vector ocspResponseList = certificateStatus.getOCSPResponseList();

                System.out.println("TLS client received a stapled ocsp_multi status with "
                    + ocspResponseList.size() + " entries:");

                for (int i = 0; i < ocspResponseList.size(); ++i)
                {
                    OCSPResponse ocspResponse = (OCSPResponse)ocspResponseList.elementAt(i);
                    if (null == ocspResponse)
                    {
                        System.out.println("    [" + i + "] no response supplied");
                    }
                    else
                    {
                        printOCSPResponse(chain.getCertificateAt(i), ocspResponse);
                    }
                }
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.bad_certificate_status_response);
            }
        }

        private void printOCSPResponse(TlsCertificate subject, OCSPResponse ocspResponse)
            throws IOException
        {
            try
            {
                Object responseObject = new OCSPResp(ocspResponse).getResponseObject();
                if (!(responseObject instanceof BasicOCSPResp))
                {
                    throw new TlsFatalAlert(AlertDescription.bad_certificate_status_response);
                }

                BasicOCSPResp basicResp = (BasicOCSPResp)responseObject;

                /*
                 * The stapled response is unauthenticated data from the peer, so it must be
                 * verified exactly as a directly fetched one would be: check the responder's
                 * signature, that the responder is authorised for this certificate's issuer, that
                 * each SingleResp's CertID actually matches the certificate being checked, and
                 * that thisUpdate/nextUpdate make the response current.
                 */
                boolean signatureValid = basicResp.isSignatureValid(new JcaContentVerifierProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caCert.getPublicKey()));

                SingleResp[] responses = basicResp.getResponses();
                for (int i = 0; i != responses.length; i++)
                {
                    SingleResp singleResp = responses[i];

                    boolean matchesSubject = singleResp.getCertID().getSerialNumber()
                        .equals(new X509CertificateHolder(subject.getEncoded()).getSerialNumber());

                    System.out.println("    serial " + singleResp.getCertID().getSerialNumber()
                        + ": " + statusText(singleResp)
                        + " (responder signature " + (signatureValid ? "valid" : "INVALID")
                        + ", CertID " + (matchesSubject ? "matches" : "DOES NOT MATCH")
                        + " the certificate it was stapled for)");
                }
            }
            catch (TlsFatalAlert e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new TlsFatalAlert(AlertDescription.bad_certificate_status_response, e);
            }
        }

        private String statusText(SingleResp singleResp)
        {
            Object status = singleResp.getCertStatus();

            if (null == status)
            {
                // org.bouncycastle.cert.ocsp.CertificateStatus.GOOD is null - see its javadoc.
                return "good";
            }
            if (status instanceof RevokedStatus)
            {
                return "revoked";
            }
            if (status instanceof UnknownStatus)
            {
                return "unknown";
            }
            return status.toString();
        }
    }

    static class ServerTask
        implements Runnable
    {
        private final InputStream input;
        private final OutputStream output;
        private final X509Certificate serverCert;
        private final X509Certificate caCert;
        private final PrivateKey privateKey;
        private final OCSPResponse ocspResponse;

        private Exception failure;

        ServerTask(InputStream input, OutputStream output, X509Certificate serverCert, X509Certificate caCert,
            PrivateKey privateKey, OCSPResponse ocspResponse)
        {
            this.input = input;
            this.output = output;
            this.serverCert = serverCert;
            this.caCert = caCert;
            this.privateKey = privateKey;
            this.ocspResponse = ocspResponse;
        }

        public void run()
        {
            try
            {
                JcaTlsCrypto crypto = new JcaTlsCryptoProvider()
                    .setProvider(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME))
                    .create(new SecureRandom());

                Certificate certificate = new Certificate(new TlsCertificate[]{
                    crypto.createCertificate(serverCert.getEncoded()),
                    crypto.createCertificate(caCert.getEncoded()) });

                TlsServerProtocol serverProtocol = new TlsServerProtocol(input, output);
                serverProtocol.accept(new StaplingTlsServer(crypto, certificate, privateKey, ocspResponse));

                try
                {
                    // Echo application data back until the client sends close_notify.
                    Streams.pipeAll(serverProtocol.getInputStream(), serverProtocol.getOutputStream());

                    serverProtocol.close();
                }
                catch (IOException e)
                {
                    /*
                     * The handshake - all this example is really about - has completed by now.
                     * With the in-memory pipes used here, the client's close() tears the pipe down
                     * as soon as its close_notify has been written, so the server's own
                     * close_notify can find nothing left to write to; a real transport would not
                     * normally produce that.
                     */
                }
            }
            catch (Exception e)
            {
                this.failure = e;
            }
        }

        void checkFailure()
            throws Exception
        {
            if (null != failure)
            {
                throw failure;
            }
        }
    }

    private static X509Certificate createCACertificate(KeyPair caKeyPair)
        throws Exception
    {
        X500Name caName = new X500Name("CN=BouncyCastle OCSP Stapling Example CA");

        JcaX509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(caName, BigInteger.valueOf(1),
            notBefore(), notAfter(), caName, caKeyPair.getPublic());

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        certBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(0))
            .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign
                | KeyUsage.digitalSignature))
            .addExtension(Extension.subjectKeyIdentifier, false,
                extUtils.createSubjectKeyIdentifier(caKeyPair.getPublic()));

        return toX509Certificate(certBldr.build(contentSigner(caKeyPair.getPrivate())));
    }

    private static X509Certificate createServerCertificate(PublicKey serverPublicKey, KeyPair caKeyPair,
        X509Certificate caCert)
        throws Exception
    {
        JcaX509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(caCert, BigInteger.valueOf(2),
            notBefore(), notAfter(), new X500Name("CN=BouncyCastle OCSP Stapling Example Server"), serverPublicKey);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        certBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
            .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment))
            .addExtension(Extension.subjectKeyIdentifier, false,
                extUtils.createSubjectKeyIdentifier(serverPublicKey))
            .addExtension(Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(caCert.getPublicKey()));

        return toX509Certificate(certBldr.build(contentSigner(caKeyPair.getPrivate())));
    }

    /**
     * Build the response the server will staple. Stands in for whatever the application really
     * uses - a cached fetch from the CA's responder, a file dropped in by a refresh job, and so on.
     */
    private static OCSPResponse createOCSPResponse(KeyPair caKeyPair, X509Certificate caCert,
        X509Certificate serverCert)
        throws Exception
    {
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME).build();

        JcaCertificateID certID = new JcaCertificateID(digCalcProv.get(RespID.HASH_SHA1), caCert,
            serverCert.getSerialNumber());

        BasicOCSPRespBuilder respBldr = new JcaBasicOCSPRespBuilder(caKeyPair.getPublic(),
            digCalcProv.get(RespID.HASH_SHA1));

        Date thisUpdate = new Date();
        Date nextUpdate = new Date(thisUpdate.getTime() + 24 * 60 * 60 * 1000L);

        // CertificateStatus.GOOD is null; a revoked certificate would take a RevokedStatus here.
        respBldr.addResponse(certID, org.bouncycastle.cert.ocsp.CertificateStatus.GOOD, thisUpdate, nextUpdate);

        BasicOCSPResp basicResp = respBldr.build(contentSigner(caKeyPair.getPrivate()),
            new X509CertificateHolder[]{ new X509CertificateHolder(caCert.getEncoded()) }, thisUpdate);

        OCSPResp ocspResp = new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basicResp);

        return OCSPResponse.getInstance(ocspResp.getEncoded());
    }

    private static org.bouncycastle.operator.ContentSigner contentSigner(PrivateKey privateKey)
        throws Exception
    {
        return new JcaContentSignerBuilder(SIG_ALG).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(privateKey);
    }

    private static X509Certificate toX509Certificate(X509CertificateHolder holder)
        throws Exception
    {
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .getCertificate(holder);
    }

    private static Date notBefore()
    {
        return new Date(System.currentTimeMillis() - 60 * 60 * 1000L);
    }

    private static Date notAfter()
    {
        return new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L);
    }
}
