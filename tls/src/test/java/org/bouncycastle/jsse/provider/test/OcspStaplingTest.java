package org.bouncycastle.jsse.provider.test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;
import java.util.Vector;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import junit.framework.TestCase;

import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.jsse.BCSSLEngine;
import org.bouncycastle.jsse.BCSSLSocket;
import org.bouncycastle.jsse.BCX509ExtendedTrustManager;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.tls.CertificateEntry;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.CertificateStatus;
import org.bouncycastle.tls.CertificateStatusRequest;
import org.bouncycastle.tls.CertificateStatusRequestItemV2;
import org.bouncycastle.tls.CertificateStatusType;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.OCSPStatusRequest;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;
import org.bouncycastle.util.Strings;

/**
 * Server-side OCSP stapling over a real handshake, in both of the shapes it takes:
 * <ul>
 * <li><b>TLS 1.2</b> - the CertificateStatus handshake message of RFC 6066 sec. 8 (status_request)
 * and RFC 6961 sec. 2.2 (status_request_v2). The BCJSSE client offers both extensions by default,
 * with status_request_v2 listing ocsp_multi ahead of ocsp, so these handshakes take the ocsp_multi
 * path - a response for the end-entity and one for the intermediate. The responses are read on the
 * client through {@link BCExtendedSSLSession#getStatusResponses()}, the same route
 * {@code ProvX509TrustManager} takes to hand them to the CertPath validator.</li>
 * <li><b>TLS 1.3</b> - a "status_request" extension on each CertificateEntry per RFC 8446
 * sec. 4.4.2.1, asserted with a low-level TLS client so the test can see which entry each staple
 * landed on.</li>
 * </ul>
 */
public class OcspStaplingTest
    extends TestCase
{
    private static final String HOST = "localhost";
    private static final String PROTOCOL = "TLSv1.2";

    private static final String PROPERTY_SERVER_ENABLE_STATUS_REQUEST =
        "jdk.tls.server.enableStatusRequestExtension";

    private static final char[] KEY_PASSWORD = "keyPassword".toCharArray();

    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    private static long serialNumber = System.currentTimeMillis();

    private TestOCSPResponder responder;

    private X509Certificate rootCert;
    private X509Certificate intermediateCert;
    private X509Certificate eeCert;
    private X509Certificate eeCertNoResponder;
    private PrivateKey eeKey;

    protected void setUp()
        throws Exception
    {
        ProviderUtils.setupHighPriority(false);

        KeyPair rootKeyPair = generateKeyPair();
        KeyPair intermediateKeyPair = generateKeyPair();
        KeyPair eeKeyPair = generateKeyPair();

        X500Name rootName = new X500Name("CN=Test OCSP Root");
        X500Name intermediateName = new X500Name("CN=Test OCSP Intermediate");

        rootCert = buildCert(rootName, rootKeyPair.getPrivate(), rootName, rootKeyPair.getPublic(),
            true, null);

        /*
         * The responder is started first so that the certificates can carry an AIA extension naming
         * the port it actually bound - stapling locates a responder the same way a client would.
         */
        responder = new TestOCSPResponder(rootKeyPair.getPublic(), rootKeyPair.getPrivate(),
            SIGNATURE_ALGORITHM, new X509CertificateHolder[]{ new X509CertificateHolder(rootCert.getEncoded()) });

        String responderURL = responder.getURL();

        intermediateCert = buildCert(rootName, rootKeyPair.getPrivate(), intermediateName,
            intermediateKeyPair.getPublic(), true, responderURL);
        eeCert = buildCert(intermediateName, intermediateKeyPair.getPrivate(), new X500Name("CN=" + HOST),
            eeKeyPair.getPublic(), false, responderURL);
        eeKey = eeKeyPair.getPrivate();

        // no AIA, so no responder can be located for it and it cannot be stapled
        eeCertNoResponder = buildCert(intermediateName, intermediateKeyPair.getPrivate(),
            new X500Name("CN=" + HOST), eeKeyPair.getPublic(), false, null);
    }

    protected void tearDown()
    {
        System.clearProperty(PROPERTY_SERVER_ENABLE_STATUS_REQUEST);

        if (null != responder)
        {
            responder.close();
        }
    }

    /**
     * Stapling has the server make outbound OCSP requests for whoever connects to it, so it must
     * stay off until asked for.
     */
    public void testDisabledByDefault()
        throws Exception
    {
        List<List<byte[]>> statusResponses = runHandshakes(1);

        assertTrue("no responses should be stapled with stapling disabled",
            statusResponses.get(0).isEmpty());
        assertEquals("the responder should not have been contacted", 0, responder.getRequestCount());
    }

    public void testStapledResponsesReachTheClient()
        throws Exception
    {
        System.setProperty(PROPERTY_SERVER_ENABLE_STATUS_REQUEST, "true");

        List<List<byte[]>> statusResponses = runHandshakes(1);

        // one for the end-entity (issued by the intermediate), one for the intermediate (by the root)
        assertStapledResponseCount(2, statusResponses.get(0));
        assertEquals(2, responder.getRequestCount());
    }

    /**
     * The point of the cache: a client cannot make the server re-ask the responder simply by
     * connecting again.
     */
    public void testResponsesAreCachedAcrossHandshakes()
        throws Exception
    {
        System.setProperty(PROPERTY_SERVER_ENABLE_STATUS_REQUEST, "true");

        List<List<byte[]>> statusResponses = runHandshakes(3);

        for (int i = 0; i != statusResponses.size(); ++i)
        {
            assertStapledResponseCount(2, statusResponses.get(i));
        }

        assertEquals("the responder should be asked once per certificate, not once per handshake", 2,
            responder.getRequestCount());
    }

    /**
     * RFC 6960 sec. 4.2.2.1: without a nextUpdate the responder is saying newer information is
     * always available, so each handshake has to ask again.
     */
    public void testResponsesWithoutNextUpdateAreNotCached()
        throws Exception
    {
        System.setProperty(PROPERTY_SERVER_ENABLE_STATUS_REQUEST, "true");

        responder.setOmitNextUpdate(true);

        List<List<byte[]>> statusResponses = runHandshakes(2);

        assertStapledResponseCount(2, statusResponses.get(0));
        assertStapledResponseCount(2, statusResponses.get(1));

        assertEquals(4, responder.getRequestCount());
    }

    /**
     * Stapling is an optimisation; its absence is not a handshake failure.
     */
    public void testUnreachableResponderDoesNotFailTheHandshake()
        throws Exception
    {
        System.setProperty(PROPERTY_SERVER_ENABLE_STATUS_REQUEST, "true");

        responder.close();

        List<List<byte[]>> statusResponses = runHandshakes(1);

        assertTrue("no responses should be stapled when the responder is unreachable",
            statusResponses.get(0).isEmpty());
    }

    /**
     * The TLS 1.3 responses reaching a BCJSSE client, read the same way as the TLS 1.2 ones.
     * <p/>
     * The list is positional - one element per certificate in the chain, zero-length where there is
     * no staple - so with the root unstapled the third element is empty rather than absent.
     */
    public void testStapledResponsesReachTheClientInTls13()
        throws Exception
    {
        System.setProperty(PROPERTY_SERVER_ENABLE_STATUS_REQUEST, "true");

        List<List<byte[]>> statusResponses = runHandshakes("TLSv1.3", defaultChain(), 1);
        List<byte[]> responses = statusResponses.get(0);

        assertEquals(3, responses.size());
        assertStapledResponse(responses.get(0));
        assertStapledResponse(responses.get(1));
        assertEquals("the root should have no staple", 0, responses.get(2).length);

        assertEquals(2, responder.getRequestCount());
    }

    /**
     * {@code ProvX509TrustManager} pairs status response <code>i</code> with certificate
     * <code>i</code> of the chain, so an entry without a staple has to hold its place. With only the
     * intermediate stapled, a response that shifted down a slot would be offered to the CertPath
     * validator as the end-entity's.
     */
    public void testStaplesStayAlignedWithTheChainInTls13()
        throws Exception
    {
        System.setProperty(PROPERTY_SERVER_ENABLE_STATUS_REQUEST, "true");

        X509Certificate[] chain = new X509Certificate[]{ eeCertNoResponder, intermediateCert, rootCert };

        List<List<byte[]>> statusResponses = runHandshakes("TLSv1.3", chain, 1);
        List<byte[]> responses = statusResponses.get(0);

        assertEquals(3, responses.size());
        assertEquals("the end-entity names no responder, so it has no staple", 0,
            responses.get(0).length);
        assertStapledResponse(responses.get(1));
        assertEquals("the root should have no staple", 0, responses.get(2).length);

        assertEquals(1, responder.getRequestCount());
    }

    /**
     * RFC 8446 sec. 4.4.2.1: in TLS 1.3 there is no CertificateStatus handshake message; each
     * CertificateEntry carries its own "status_request" extension whose body is an RFC 6066
     * CertificateStatus. Asserted with a low-level TLS client, which can read the extensions off the
     * Certificate message directly and so pin down which entry each staple landed on.
     */
    public void testStapledResponsesInTls13CertificateEntries()
        throws Exception
    {
        System.setProperty(PROPERTY_SERVER_ENABLE_STATUS_REQUEST, "true");

        SSLServerSocket sSock = createServerSocket("TLSv1.3", defaultChain());
        try
        {
            CapturingTlsClient client = new CapturingTlsClient(ProtocolVersion.TLSv13,
                ocspStatusRequest(null), null);

            runLowLevelClient(sSock, client);

            CertificateEntry[] certificateEntryList = client.certificateEntryList;
            assertNotNull("no server Certificate message was seen", certificateEntryList);

            // the chain is end-entity, intermediate, root
            assertEquals(3, certificateEntryList.length);

            assertStapledCertificateEntry(certificateEntryList[0]);
            assertStapledCertificateEntry(certificateEntryList[1]);

            // the root has no issuer in the chain to identify it to a responder
            Hashtable rootExtensions = certificateEntryList[2].getExtensions();
            assertTrue("the last entry should carry no staple",
                null == rootExtensions || null == rootExtensions.get(TlsExtensionsUtils.EXT_status_request));

            assertEquals(2, responder.getRequestCount());
        }
        finally
        {
            sSock.close();
        }
    }

    /**
     * RFC 6066 sec. 8 on its own: a client offering status_request but not status_request_v2 gets a
     * CertificateStatus of type ocsp, covering the end-entity only. The BCJSSE client always offers
     * both extensions, so this one is driven by a low-level client.
     */
    public void testStatusRequestWithoutStatusRequestV2()
        throws Exception
    {
        System.setProperty(PROPERTY_SERVER_ENABLE_STATUS_REQUEST, "true");

        CapturingTlsClient client = new CapturingTlsClient(ProtocolVersion.TLSv12,
            ocspStatusRequest(null), null);

        CertificateStatus certificateStatus = runForCertificateStatus(client);

        assertNotNull("no CertificateStatus message was sent", certificateStatus);
        assertEquals(CertificateStatusType.ocsp, certificateStatus.getStatusType());
        assertOcspResponse(certificateStatus.getOCSPResponse());

        assertEquals("only the end-entity should have been asked about", 1,
            responder.getRequestCount());
    }

    /**
     * RFC 6961 sec. 2.2 where the client offers status_request_v2 with an ocsp item but no
     * ocsp_multi: the answer is a single response for the end-entity, not a list.
     */
    public void testStatusRequestV2WithOnlyAnOcspItem()
        throws Exception
    {
        System.setProperty(PROPERTY_SERVER_ENABLE_STATUS_REQUEST, "true");

        Vector multiStatusRequest = new Vector();
        multiStatusRequest.add(new CertificateStatusRequestItemV2(CertificateStatusType.ocsp,
            new OCSPStatusRequest(null, null)));

        CapturingTlsClient client = new CapturingTlsClient(ProtocolVersion.TLSv12, null,
            multiStatusRequest);

        CertificateStatus certificateStatus = runForCertificateStatus(client);

        assertNotNull("no CertificateStatus message was sent", certificateStatus);
        assertEquals(CertificateStatusType.ocsp, certificateStatus.getStatusType());
        assertOcspResponse(certificateStatus.getOCSPResponse());

        assertEquals("only the end-entity should have been asked about", 1,
            responder.getRequestCount());
    }

    /**
     * A non-empty responder_id_list asks for an answer from one of a named set of responders, which
     * this server cannot honour. It leaves the request unanswered rather than answering it with
     * something a different responder said.
     */
    public void testStatusRequestNamingRespondersIsNotAnswered()
        throws Exception
    {
        System.setProperty(PROPERTY_SERVER_ENABLE_STATUS_REQUEST, "true");

        Vector responderIDList = new Vector();
        responderIDList.add(new ResponderID(new X500Name("CN=Some Other Responder")));

        CapturingTlsClient client = new CapturingTlsClient(ProtocolVersion.TLSv12,
            ocspStatusRequest(responderIDList), null);

        CertificateStatus certificateStatus = runForCertificateStatus(client);

        assertNull("no CertificateStatus message should have been sent", certificateStatus);
        assertEquals("the responder should not have been contacted", 0, responder.getRequestCount());
    }

    /**
     * Echoing status_request_v2 commits the server to answering from the v2 item list alone, so it
     * only does so for a list it can answer from. A client offering both extensions, whose every v2
     * item names responders this server cannot speak for, still gets its plain status_request
     * answered - where taking v2 regardless would leave it with no staple at all.
     */
    public void testUnanswerableStatusRequestV2FallsBackToStatusRequest()
        throws Exception
    {
        System.setProperty(PROPERTY_SERVER_ENABLE_STATUS_REQUEST, "true");

        Vector responderIDList = new Vector();
        responderIDList.add(new ResponderID(new X500Name("CN=Some Other Responder")));

        Vector multiStatusRequest = new Vector();
        multiStatusRequest.add(new CertificateStatusRequestItemV2(CertificateStatusType.ocsp_multi,
            new OCSPStatusRequest(responderIDList, null)));

        CapturingTlsClient client = new CapturingTlsClient(ProtocolVersion.TLSv12,
            ocspStatusRequest(null), multiStatusRequest);

        CertificateStatus certificateStatus = runForCertificateStatus(client);

        assertNotNull("the answerable status_request should have been answered", certificateStatus);
        assertEquals(CertificateStatusType.ocsp, certificateStatus.getStatusType());
        assertOcspResponse(certificateStatus.getOCSPResponse());

        assertEquals("only the end-entity should have been asked about", 1,
            responder.getRequestCount());
    }

    /**
     * RFC 6961 sec. 2.2 has the item list "in order of the client's preference", so the first item
     * that can be answered is the one answered - an ocsp_multi further down the list does not
     * outrank an ocsp item the client put first, however much more it would have covered.
     */
    public void testStatusRequestV2TakesTheClientsFirstAnswerableItem()
        throws Exception
    {
        System.setProperty(PROPERTY_SERVER_ENABLE_STATUS_REQUEST, "true");

        Vector multiStatusRequest = new Vector();
        multiStatusRequest.add(new CertificateStatusRequestItemV2(CertificateStatusType.ocsp,
            new OCSPStatusRequest(null, null)));
        multiStatusRequest.add(new CertificateStatusRequestItemV2(CertificateStatusType.ocsp_multi,
            new OCSPStatusRequest(null, null)));

        CapturingTlsClient client = new CapturingTlsClient(ProtocolVersion.TLSv12, null,
            multiStatusRequest);

        CertificateStatus certificateStatus = runForCertificateStatus(client);

        assertNotNull("no CertificateStatus message was sent", certificateStatus);
        assertEquals("the client asked by ocsp first", CertificateStatusType.ocsp,
            certificateStatus.getStatusType());
        assertOcspResponse(certificateStatus.getOCSPResponse());

        assertEquals("an ocsp item covers the end-entity only", 1, responder.getRequestCount());
    }

    private CertificateStatus runForCertificateStatus(CapturingTlsClient client)
        throws Exception
    {
        SSLServerSocket sSock = createServerSocket(PROTOCOL, defaultChain());
        try
        {
            runLowLevelClient(sSock, client);

            assertNotNull("no server Certificate message was seen", client.certificateEntryList);

            return client.certificateStatus;
        }
        finally
        {
            sSock.close();
        }
    }

    private void assertOcspResponse(OCSPResponse ocspResponse)
        throws IOException
    {
        assertNotNull(ocspResponse);
        assertEquals(OCSPResponseStatus.SUCCESSFUL, ocspResponse.getResponseStatus().getIntValue());
    }

    /**
     * The status_request extension body is a CertificateStatus: a one-byte status type followed by
     * the DER response in a 24-bit length field. Decoded here rather than through
     * {@code CertificateStatus.parse}, which wants a TlsContext this test has no handle on.
     */
    private void assertStapledCertificateEntry(CertificateEntry certificateEntry)
        throws IOException
    {
        Hashtable extensions = certificateEntry.getExtensions();
        assertNotNull("entry carries no extensions", extensions);

        byte[] extensionData = (byte[])extensions.get(TlsExtensionsUtils.EXT_status_request);
        assertNotNull("entry carries no status_request extension", extensionData);

        assertTrue(extensionData.length > 4);
        assertEquals(CertificateStatusType.ocsp, extensionData[0] & 0xFF);

        int length = ((extensionData[1] & 0xFF) << 16) | ((extensionData[2] & 0xFF) << 8)
            | (extensionData[3] & 0xFF);
        assertEquals(extensionData.length - 4, length);

        byte[] derResponse = new byte[length];
        System.arraycopy(extensionData, 4, derResponse, 0, length);

        OCSPResponse ocspResponse = OCSPResponse.getInstance(derResponse);
        assertEquals(OCSPResponseStatus.SUCCESSFUL, ocspResponse.getResponseStatus().getIntValue());
    }

    private void runLowLevelClient(SSLServerSocket sSock, CapturingTlsClient client)
        throws Exception
    {
        final Exception[] serverFailure = new Exception[1];
        Thread serverThread = startEchoServer(sSock, serverFailure);

        Socket socket = new Socket(HOST, sSock.getLocalPort());
        try
        {
            TlsClientProtocol protocol = new TlsClientProtocol(socket.getInputStream(),
                socket.getOutputStream());
            protocol.connect(client);

            OutputStream output = protocol.getOutputStream();
            output.write('!');
            output.flush();

            assertEquals('!', protocol.getInputStream().read());

            protocol.close();
        }
        finally
        {
            socket.close();
        }

        serverThread.join(30000);

        if (null != serverFailure[0])
        {
            throw serverFailure[0];
        }
    }

    private static CertificateStatusRequest ocspStatusRequest(Vector responderIDList)
    {
        return new CertificateStatusRequest(CertificateStatusType.ocsp,
            new OCSPStatusRequest(responderIDList, null));
    }

    private void assertStapledResponseCount(int expected, List<byte[]> statusResponses)
        throws IOException
    {
        assertEquals(expected, statusResponses.size());

        for (int i = 0; i != statusResponses.size(); ++i)
        {
            assertStapledResponse(statusResponses.get(i));
        }
    }

    private void assertStapledResponse(byte[] statusResponse)
        throws IOException
    {
        assertTrue("stapled response is empty", statusResponse.length > 0);

        OCSPResponse ocspResponse = OCSPResponse.getInstance(statusResponse);
        assertEquals(OCSPResponseStatus.SUCCESSFUL, ocspResponse.getResponseStatus().getIntValue());
    }

    /**
     * Run <code>count</code> sequential handshakes against one server SSLContext - the same context,
     * so the same stapling cache - and return what each client saw stapled.
     */
    private List<List<byte[]>> runHandshakes(int count)
        throws Exception
    {
        return runHandshakes(PROTOCOL, defaultChain(), count);
    }

    private List<List<byte[]>> runHandshakes(String protocol, X509Certificate[] chain, int count)
        throws Exception
    {
        SSLServerSocket sSock = createServerSocket(protocol, chain);

        try
        {
            List<List<byte[]>> result = new ArrayList<List<byte[]>>(count);

            for (int i = 0; i != count; ++i)
            {
                /*
                 * A fresh client context per handshake, so each one is a full handshake rather than a
                 * resumption - a resumed session carries no Certificate message and so no
                 * CertificateStatus, which would leave these assertions measuring nothing. The
                 * server context is the one held across the loop, and with it the stapling cache.
                 */
                StatusResponseCapture capture = new StatusResponseCapture();

                SSLContext clientContext = SSLContext.getInstance("TLS",
                    ProviderUtils.PROVIDER_NAME_BCJSSE);
                clientContext.init(null, new TrustManager[]{ capture },
                    SecureRandom.getInstance("DEFAULT", ProviderUtils.PROVIDER_NAME_BC));

                doHandshake(clientContext, sSock, protocol);

                result.add(capture.getStatusResponses());
            }

            return result;
        }
        finally
        {
            sSock.close();
        }
    }

    /**
     * A server socket whose SSLContext - and so whose stapling cache - lives as long as the socket.
     */
    private X509Certificate[] defaultChain()
    {
        return new X509Certificate[]{ eeCert, intermediateCert, rootCert };
    }

    private SSLServerSocket createServerSocket(String protocol, X509Certificate[] chain)
        throws Exception
    {
        KeyStore serverStore = createKeyStore();
        serverStore.setKeyEntry("server", eeKey, KEY_PASSWORD, chain);

        KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("PKIX",
            ProviderUtils.PROVIDER_NAME_BCJSSE);
        keyMgrFact.init(serverStore, KEY_PASSWORD);

        SSLContext serverContext = SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE);
        serverContext.init(keyMgrFact.getKeyManagers(), null,
            SecureRandom.getInstance("DEFAULT", ProviderUtils.PROVIDER_NAME_BC));

        SSLServerSocketFactory serverFact = serverContext.getServerSocketFactory();
        SSLServerSocket sSock = (SSLServerSocket)serverFact.createServerSocket(0);
        sSock.setEnabledProtocols(new String[]{ protocol });

        return sSock;
    }

    /**
     * Accepts one connection and echoes a byte, which is enough to drive a handshake to completion.
     */
    private Thread startEchoServer(final ServerSocket serverSocket, final Exception[] serverFailure)
    {
        Thread serverThread = new Thread(new Runnable()
        {
            public void run()
            {
                Socket socket = null;
                try
                {
                    socket = serverSocket.accept();

                    InputStream input = socket.getInputStream();
                    OutputStream output = socket.getOutputStream();

                    int b = input.read();
                    output.write(b);
                    output.flush();
                }
                catch (Exception e)
                {
                    serverFailure[0] = e;
                }
                finally
                {
                    if (null != socket)
                    {
                        try
                        {
                            socket.close();
                        }
                        catch (IOException e)
                        {
                            // ignore
                        }
                    }
                }
            }
        }, "OcspStaplingTest-server");

        serverThread.setDaemon(true);
        serverThread.start();

        return serverThread;
    }

    private void doHandshake(SSLContext clientContext, SSLServerSocket sSock, String protocol)
        throws Exception
    {
        final Exception[] serverFailure = new Exception[1];

        Thread serverThread = startEchoServer(sSock, serverFailure);

        SSLSocketFactory clientFact = clientContext.getSocketFactory();
        SSLSocket cSock = (SSLSocket)clientFact.createSocket(HOST, sSock.getLocalPort());
        try
        {
            cSock.setEnabledProtocols(new String[]{ protocol });
            cSock.startHandshake();

            cSock.getOutputStream().write('!');
            cSock.getOutputStream().flush();
            assertEquals('!', cSock.getInputStream().read());
        }
        finally
        {
            cSock.close();
        }

        serverThread.join(30000);

        if (null != serverFailure[0])
        {
            throw serverFailure[0];
        }
    }

    private static KeyStore createKeyStore()
        throws GeneralSecurityException, IOException
    {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", ProviderUtils.PROVIDER_NAME_BC);
        keyStore.load(null, null);
        return keyStore;
    }

    private static KeyPair generateKeyPair()
        throws GeneralSecurityException
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", ProviderUtils.PROVIDER_NAME_BC);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static X509Certificate buildCert(X500Name issuer, PrivateKey issuerKey, X500Name subject,
        PublicKey subjectKey, boolean ca, String ocspResponderURL)
        throws Exception
    {
        long now = System.currentTimeMillis();

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuer,
            BigInteger.valueOf(++serialNumber), new Date(now - 60 * 1000L),
            new Date(now + 24 * 3600 * 1000L), subject,
            SubjectPublicKeyInfo.getInstance(subjectKey.getEncoded()));

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));

        if (null != ocspResponderURL)
        {
            builder.addExtension(Extension.authorityInfoAccess, false,
                new AuthorityInformationAccess(AccessDescription.id_ad_ocsp,
                    new GeneralName(GeneralName.uniformResourceIdentifier, ocspResponderURL)));
        }

        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
            .setProvider(ProviderUtils.PROVIDER_NAME_BC).build(issuerKey);

        return new JcaX509CertificateConverter()
            .setProvider(ProviderUtils.PROVIDER_NAME_BC).getCertificate(builder.build(signer));
    }

    /**
     * A low-level TLS 1.3 client that asks for status_request and keeps the server's CertificateEntry
     * list, so a test can see exactly which entries carried a staple. It accepts any certificate -
     * what is under test is the stapling, not the validation of what it accompanies.
     */
    private static class CapturingTlsClient
        extends DefaultTlsClient
    {
        private final ProtocolVersion[] protocolVersions;
        private final CertificateStatusRequest statusRequest;
        private final Vector multiStatusRequest;

        CertificateEntry[] certificateEntryList = null;
        CertificateStatus certificateStatus = null;

        /**
         * @param statusRequest      the status_request to offer, or null to offer none.
         * @param multiStatusRequest the status_request_v2 items to offer, or null to offer none.
         *                           Ignored by the protocol for TLS 1.3, which has no such extension.
         */
        CapturingTlsClient(ProtocolVersion protocolVersion, CertificateStatusRequest statusRequest,
            Vector multiStatusRequest)
            throws GeneralSecurityException
        {
            super(new JcaTlsCryptoProvider().setProvider(ProviderUtils.PROVIDER_NAME_BC)
                .create(new SecureRandom()));

            this.protocolVersions = protocolVersion.only();
            this.statusRequest = statusRequest;
            this.multiStatusRequest = multiStatusRequest;
        }

        protected ProtocolVersion[] getSupportedVersions()
        {
            return protocolVersions;
        }

        protected CertificateStatusRequest getCertificateStatusRequest()
        {
            return statusRequest;
        }

        protected Vector getMultiCertStatusRequest()
        {
            return multiStatusRequest;
        }

        public TlsAuthentication getAuthentication()
        {
            return new TlsAuthentication()
            {
                public void notifyServerCertificate(TlsServerCertificate serverCertificate)
                {
                    certificateEntryList = serverCertificate.getCertificate().getCertificateEntryList();
                    certificateStatus = serverCertificate.getCertificateStatus();
                }

                public TlsCredentials getClientCredentials(CertificateRequest certificateRequest)
                {
                    return null;
                }
            };
        }
    }

    /**
     * Reads the stapled responses where a real caller would: from the handshake session, inside the
     * trust manager callback. Accepts any chain - what is under test is the stapling, not the
     * validation of the certificates it accompanies.
     */
    private static class StatusResponseCapture
        extends BCX509ExtendedTrustManager
    {
        private List<byte[]> statusResponses = Collections.emptyList();

        synchronized List<byte[]> getStatusResponses()
        {
            return statusResponses;
        }

        private synchronized void capture(List<byte[]> statusResponses)
        {
            this.statusResponses = statusResponses;
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException
        {
            BCExtendedSSLSession session = ((BCSSLSocket)socket).getBCHandshakeSession();

            capture(session.getStatusResponses());
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException
        {
            capture(((BCSSLEngine)engine).getBCHandshakeSession().getStatusResponses());
        }

        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException
        {
        }

        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException
        {
        }

        public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException
        {
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException
        {
        }

        public X509Certificate[] getAcceptedIssuers()
        {
            return new X509Certificate[0];
        }
    }
}
