package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.Hashtable;
import java.util.Vector;

import junit.framework.TestCase;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateEntry;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.CertificateStatus;
import org.bouncycastle.tls.CertificateStatusRequest;
import org.bouncycastle.tls.CertificateStatusRequestItemV2;
import org.bouncycastle.tls.CertificateStatusType;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.ExtensionType;
import org.bouncycastle.tls.OCSPStatusRequest;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsObjectIdentifiers;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

/**
 * OCSP stapling with the low-level API in TLS 1.3, where RFC 8446 sec. 4.4.2.1 replaces the
 * "certificate_status" handshake message with a "status_request" extension on the CertificateEntry
 * carrying the certificate the response answers for.
 * <p/>
 * A server supplies these through the same {@link org.bouncycastle.tls.TlsServer#getCertificateStatus()}
 * callback it uses up to TLS 1.2, and the protocol distributes what it returns over the entries -
 * previously a server had to build the extensions and attach them to the {@link Certificate} its
 * credentials supplied, which the last case here shows still works.
 * <p/>
 * The RFC 7633 TLS feature ("must-staple") checks a client makes of what arrives are here too, with
 * their TLS 1.2 counterparts alongside.
 */
public class Tls13CertificateStatusTest
    extends TestCase
{
    private static final String[] CERT_CHAIN = new String[]{ "x509-server-rsa-sign.pem", "x509-ca-rsa.pem" };
    private static final String KEY_RESOURCE = "x509-server-key-rsa-sign.pem";
    private static final String CA_KEY_RESOURCE = "x509-ca-key-rsa.pem";

    private static final int[] MUST_STAPLE = new int[]{ ExtensionType.status_request };
    private static final int[] MULTI_CERT_MUST_STAPLE = new int[]{ ExtensionType.status_request_v2 };

    public void testOcspMultiIsDistributedAcrossCertificateEntries()
        throws Exception
    {
        Vector ocspResponseList = new Vector();
        ocspResponseList.addElement(ocspResponse("end-entity"));
        ocspResponseList.addElement(ocspResponse("intermediate"));

        CertificateEntry[] certificateEntryList = runHandshake(
            new CertificateStatus(CertificateStatusType.ocsp_multi, ocspResponseList), false);

        assertEquals(2, certificateEntryList.length);
        assertEquals("end-entity", getStapledMarker(certificateEntryList[0]));
        assertEquals("intermediate", getStapledMarker(certificateEntryList[1]));
    }

    /**
     * The ocsp shape answers for the end-entity certificate alone, as it does in the
     * "certificate_status" message of TLS 1.2 - the rest of the chain simply goes unstapled.
     */
    public void testSingleOcspStatusAnswersTheEndEntityOnly()
        throws Exception
    {
        CertificateEntry[] certificateEntryList = runHandshake(
            new CertificateStatus(CertificateStatusType.ocsp, ocspResponse("end-entity")), false);

        assertEquals(2, certificateEntryList.length);
        assertEquals("end-entity", getStapledMarker(certificateEntryList[0]));
        assertNull("the rest of the chain should carry no staple",
            getStapledMarker(certificateEntryList[1]));
    }

    /**
     * A null status is how a server declines, and it must leave the Certificate message as it was -
     * an entry carrying an empty extensions table would be a change in what goes on the wire.
     */
    public void testNoStatusLeavesTheEntriesAlone()
        throws Exception
    {
        CertificateEntry[] certificateEntryList = runHandshake(null, false);

        assertEquals(2, certificateEntryList.length);
        assertNull(getStapledMarker(certificateEntryList[0]));
        assertNull(getStapledMarker(certificateEntryList[1]));
    }

    /**
     * A server that attaches its own staple to the Certificate its credentials supply - the only way
     * to do this before the callback was consulted in TLS 1.3 - keeps the extension it built, even
     * where the callback offers a response for the same entry.
     */
    public void testServerSuppliedEntryExtensionIsPreserved()
        throws Exception
    {
        Vector ocspResponseList = new Vector();
        ocspResponseList.addElement(ocspResponse("from-callback"));
        ocspResponseList.addElement(ocspResponse("from-callback"));

        CertificateEntry[] certificateEntryList = runHandshake(
            new CertificateStatus(CertificateStatusType.ocsp_multi, ocspResponseList), true);

        assertEquals(2, certificateEntryList.length);
        assertEquals("from-callback", getStapledMarker(certificateEntryList[0]));
        assertEquals("attached-by-server", getStapledMarker(certificateEntryList[1]));
    }

    /**
     * The read side of the same wire form: a client hands the staples back per certificate through
     * {@link TlsServerCertificate#getCertificateStatusAt(int)}, whichever entry each arrived in, and
     * {@link TlsServerCertificate#getCertificateStatus()} answers for the end-entity certificate as
     * it does up to TLS 1.2.
     */
    public void testClientReadsAStapleForEachCertificate()
        throws Exception
    {
        Vector ocspResponseList = new Vector();
        ocspResponseList.addElement(ocspResponse("end-entity"));
        ocspResponseList.addElement(ocspResponse("intermediate"));

        TlsServerCertificate serverCertificate = runHandshake(
            new CertificateStatus(CertificateStatusType.ocsp_multi, ocspResponseList), false, true)
            .serverCertificate;

        assertEquals(2, serverCertificate.getCertificate().getLength());
        assertEquals("end-entity", getMarker(serverCertificate.getCertificateStatusAt(0)));
        assertEquals("intermediate", getMarker(serverCertificate.getCertificateStatusAt(1)));
        assertEquals("end-entity", getMarker(serverCertificate.getCertificateStatus()));
    }

    /**
     * A single response answers for the end-entity certificate, so the rest of the chain reads back
     * unstapled rather than picking up the one response that did arrive.
     */
    public void testClientReadsSingleOcspAgainstTheEndEntityOnly()
        throws Exception
    {
        TlsServerCertificate serverCertificate = runHandshake(
            new CertificateStatus(CertificateStatusType.ocsp, ocspResponse("end-entity")), false, true)
            .serverCertificate;

        assertEquals("end-entity", getMarker(serverCertificate.getCertificateStatusAt(0)));
        assertNull(getMarker(serverCertificate.getCertificateStatusAt(1)));
        assertEquals("end-entity", getMarker(serverCertificate.getCertificateStatus()));
    }

    public void testClientReadsNoStatusWhereNoneWasStapled()
        throws Exception
    {
        TlsServerCertificate serverCertificate = runHandshake(null, false, true).serverCertificate;

        assertNull(serverCertificate.getCertificateStatus());
        assertNull(serverCertificate.getCertificateStatusAt(0));
        assertNull(serverCertificate.getCertificateStatusAt(1));
    }

    /**
     * An index that is not an index of getCertificate() names no certificate, so it has no status:
     * null, rather than an exception, since the interface gives a caller no count to check against
     * other than the chain's own length.
     */
    public void testClientReadsNullOutsideTheChain()
        throws Exception
    {
        Vector ocspResponseList = new Vector();
        ocspResponseList.addElement(ocspResponse("end-entity"));
        ocspResponseList.addElement(ocspResponse("intermediate"));

        TlsServerCertificate serverCertificate = runHandshake(
            new CertificateStatus(CertificateStatusType.ocsp_multi, ocspResponseList), false, true)
            .serverCertificate;

        int length = serverCertificate.getCertificate().getLength();
        assertEquals(2, length);
        assertNull(serverCertificate.getCertificateStatusAt(-1));
        assertNull(serverCertificate.getCertificateStatusAt(length));
        assertNull(serverCertificate.getCertificateStatusAt(Integer.MAX_VALUE));
    }

    /**
     * RFC 8446 sec. 4.2: a server answers only the extensions the client sent, and an endpoint
     * receiving any other MUST abort the handshake with unsupported_extension - so a staple the client
     * never asked for fails it. The staple has to be attached to the Certificate by hand here, the
     * protocol declining to consult getCertificateStatus() for a client that did not ask.
     */
    public void testClientRejectsAnUnsolicitedStaple()
        throws Exception
    {
        byte[] extensionData = TlsExtensionsUtils.createStatusRequestExtension13(
            new CertificateStatus(CertificateStatusType.ocsp, ocspResponse("unsolicited")));

        CapturingTlsClient client = new CapturingTlsClient(false);

        try
        {
            runHandshake(client, null, false, extensionData);
            fail("expected an unsupported_extension");
        }
        catch (Exception e)
        {
            assertClientFailedWith(client, AlertDescription.unsupported_extension);
        }
    }

    /**
     * Every CertificateEntry is held to the ClientHello, not just the end-entity certificate's.
     */
    public void testClientRejectsAnUnsolicitedStapleOnAnIntermediate()
        throws Exception
    {
        CapturingTlsClient client = new CapturingTlsClient(false);

        try
        {
            runHandshake(client, null, true, null);
            fail("expected an unsupported_extension");
        }
        catch (Exception e)
        {
            assertClientFailedWith(client, AlertDescription.unsupported_extension);
        }
    }

    /**
     * RFC 8446 sec. 4.4.2.1 admits only an RFC 6066 CertificateStatus of type ocsp in the extension,
     * so anything else is a decode_error, as it is for the TLS 1.2 "certificate_status" message. A
     * client that asked for a staple now reads what arrives, so a server that mis-staples no longer
     * goes unnoticed.
     */
    public void testMalformedStapleFailsTheHandshake()
        throws Exception
    {
        CapturingTlsClient client = new CapturingTlsClient(true);

        try
        {
            runHandshake(client, null, false, Strings.toByteArray("not a CertificateStatus"));
            fail("expected a decode_error");
        }
        catch (Exception e)
        {
            /*
             * The client's own exception is the one that says why: runHandshake rethrows the server's
             * in preference, and all the server saw was the pipe closing under it.
             */
            assertTrue("client failed with " + client.failure, client.failure instanceof TlsFatalAlert);
            assertEquals(AlertDescription.decode_error, ((TlsFatalAlert)client.failure).getAlertDescription());
        }
    }

    /*
     * RFC 7633 TLS feature ("must-staple") checks. A feature listing a status request is only
     * satisfied by an actual response for the end-entity certificate: from TLS 1.3 that arrives in its
     * CertificateEntry (never in EncryptedExtensions), and up to TLS 1.2 the ServerHello echo alone is
     * not enough, since RFC 6066 sec. 8 lets a server then omit the "certificate_status" message.
     */

    /**
     * github #2458: RFC 8446 sec. 4.4.2.1 puts a TLS 1.3 server's staple in the CertificateEntry, so
     * that is where a must-staple end-entity certificate has to be satisfied from.
     */
    public void testMustStapleIsSatisfiedByTheCertificateEntryStaple()
        throws Exception
    {
        CapturingTlsClient client = new CapturingTlsClient(true);

        runTlsFeatureHandshake(client, MUST_STAPLE, ocspSingle("end-entity"), false);

        assertEquals(ProtocolVersion.TLSv13, client.negotiatedVersion);
        assertEquals("end-entity", getMarker(client.serverCertificate.getCertificateStatus()));
    }

    public void testMustStapleFailsWithoutAStaple()
        throws Exception
    {
        CapturingTlsClient client = new CapturingTlsClient(true);

        try
        {
            runTlsFeatureHandshake(client, MUST_STAPLE, null, false);
            fail("expected a certificate_unknown");
        }
        catch (Exception e)
        {
            assertEquals(ProtocolVersion.TLSv13, client.negotiatedVersion);
            assertClientFailedWith(client, AlertDescription.certificate_unknown);
        }
    }

    /**
     * RFC 7633 sec. 4.3.3: a feature is only in force where the client's ClientHello offered it too.
     */
    public void testMustStapleIsNotInForceUnlessRequested()
        throws Exception
    {
        CapturingTlsClient client = new CapturingTlsClient(false);

        runTlsFeatureHandshake(client, MUST_STAPLE, null, false);

        assertEquals(ProtocolVersion.TLSv13, client.negotiatedVersion);
        assertNull(client.serverCertificate.getCertificateStatus());
    }

    public void testTls12MustStapleIsSatisfiedByTheCertificateStatusMessage()
        throws Exception
    {
        CapturingTlsClient client = new CapturingTlsClient(true);
        client.supportedVersions = ProtocolVersion.TLSv12.only();

        runTlsFeatureHandshake(client, MUST_STAPLE, ocspSingle("end-entity"), false);

        assertEquals(ProtocolVersion.TLSv12, client.negotiatedVersion);
        assertEquals("end-entity", getMarker(client.serverCertificate.getCertificateStatus()));
    }

    /**
     * The server echoes "status_request" - as AbstractTlsServer does whenever the client offered it -
     * but, holding no status, sends no "certificate_status" message. RFC 6066 sec. 8 permits that, so
     * the echo alone would let anyone holding the key of a revoked must-staple certificate simply not
     * staple.
     */
    public void testTls12MustStapleFailsOnAnEchoWithoutAStatus()
        throws Exception
    {
        CapturingTlsClient client = new CapturingTlsClient(true);
        client.supportedVersions = ProtocolVersion.TLSv12.only();

        try
        {
            runTlsFeatureHandshake(client, MUST_STAPLE, null, false);
            fail("expected a certificate_unknown");
        }
        catch (Exception e)
        {
            assertEquals(ProtocolVersion.TLSv12, client.negotiatedVersion);
            assertClientFailedWith(client, AlertDescription.certificate_unknown);
        }
    }

    public void testTls12MultiCertMustStapleIsSatisfiedByAnEndEntityResponse()
        throws Exception
    {
        CapturingTlsClient client = new CapturingTlsClient(false);
        client.supportedVersions = ProtocolVersion.TLSv12.only();
        client.requestMultiCertStatus = true;

        CertificateStatus certificateStatus = ocspMulti(ocspResponse("end-entity"), ocspResponse("intermediate"));

        runTlsFeatureHandshake(client, MULTI_CERT_MUST_STAPLE, certificateStatus, true);

        assertEquals(ProtocolVersion.TLSv12, client.negotiatedVersion);
        assertEquals("end-entity", getMarker(client.serverCertificate.getCertificateStatusAt(0)));
    }

    /**
     * RFC 6961 sec. 2.2 lets an element of the list be absent, so an ocsp_multi status can arrive
     * holding nothing for the end-entity certificate - which answers nothing for must-staple, however
     * much it holds for the rest of the chain.
     */
    public void testTls12MultiCertMustStapleFailsWithoutAnEndEntityResponse()
        throws Exception
    {
        CapturingTlsClient client = new CapturingTlsClient(false);
        client.supportedVersions = ProtocolVersion.TLSv12.only();
        client.requestMultiCertStatus = true;

        CertificateStatus certificateStatus = ocspMulti(null, ocspResponse("intermediate"));

        try
        {
            runTlsFeatureHandshake(client, MULTI_CERT_MUST_STAPLE, certificateStatus, true);
            fail("expected a certificate_unknown");
        }
        catch (Exception e)
        {
            assertEquals(ProtocolVersion.TLSv12, client.negotiatedVersion);
            assertClientFailedWith(client, AlertDescription.certificate_unknown);
        }
    }

    /**
     * RFC 8446 sec. 4.2 has no place for "status_request_v2", so a TLS 1.3 server has no way to answer
     * it, and the feature is not in force once TLS 1.3 is negotiated - even though a client that also
     * offers TLS 1.2 sends it.
     */
    public void testMultiCertMustStapleIsNotInForceInTls13()
        throws Exception
    {
        CapturingTlsClient client = new CapturingTlsClient(false);
        client.supportedVersions = ProtocolVersion.TLSv13.downTo(ProtocolVersion.TLSv12);
        client.requestMultiCertStatus = true;

        runTlsFeatureHandshake(client, MULTI_CERT_MUST_STAPLE, null, false);

        assertEquals(ProtocolVersion.TLSv13, client.negotiatedVersion);
    }

    private static void assertClientFailedWith(CapturingTlsClient client, short alertDescription)
    {
        assertTrue("client failed with " + client.failure, client.failure instanceof TlsFatalAlert);
        assertEquals(alertDescription, ((TlsFatalAlert)client.failure).getAlertDescription());
    }

    /**
     * Drives a handshake against a server that supports TLS 1.2 and 1.3 - so the client's versions
     * decide - and whose end-entity certificate carries a TLS feature extension listing
     * <code>tlsFeatures</code>.
     *
     * @param multiCertStatus have the server answer "status_request_v2".
     */
    private void runTlsFeatureHandshake(CapturingTlsClient client, int[] tlsFeatures,
        CertificateStatus certificateStatus, boolean multiCertStatus) throws Exception
    {
        StatusStaplingTlsServer server = new StatusStaplingTlsServer(certificateStatus, false, null);
        server.supportedVersions = ProtocolVersion.TLSv13.downTo(ProtocolVersion.TLSv12);
        server.tlsFeatures = tlsFeatures;
        server.multiCertStatus = multiCertStatus;

        runHandshake(client, server);
    }

    /**
     * @param attachToSecondEntry have the server attach a staple of its own to the second entry of
     *                            the Certificate its credentials supply.
     * @return the CertificateEntry list the client received.
     */
    private CertificateEntry[] runHandshake(CertificateStatus certificateStatus, boolean attachToSecondEntry)
        throws Exception
    {
        return runHandshake(certificateStatus, attachToSecondEntry, true).certificateEntryList;
    }

    private CapturingTlsClient runHandshake(CertificateStatus certificateStatus, boolean attachToSecondEntry,
        boolean requestStatus) throws Exception
    {
        return runHandshake(certificateStatus, attachToSecondEntry, requestStatus, null);
    }

    /**
     * @param requestStatus       have the client ask for a staple at all.
     * @param malformedExtension  a "status_request" extension body for the server to attach to the
     *                            first entry in place of a well formed one, or null for none.
     */
    private CapturingTlsClient runHandshake(CertificateStatus certificateStatus, boolean attachToSecondEntry,
        boolean requestStatus, byte[] malformedExtension) throws Exception
    {
        CapturingTlsClient capturingTlsClient = new CapturingTlsClient(requestStatus);
        runHandshake(capturingTlsClient, certificateStatus, attachToSecondEntry, malformedExtension);
        return capturingTlsClient;
    }

    /**
     * Drives a handshake with a caller-supplied client, so that where it fails the caller still has
     * the client - and its {@link CapturingTlsClient#failure} - in hand.
     */
    private void runHandshake(CapturingTlsClient client, CertificateStatus certificateStatus,
        boolean attachToSecondEntry, byte[] malformedExtension) throws Exception
    {
        runHandshake(client, new StatusStaplingTlsServer(certificateStatus, attachToSecondEntry,
            malformedExtension));
    }

    private void runHandshake(CapturingTlsClient client, StatusStaplingTlsServer server) throws Exception
    {
        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        ServerThread serverThread = new ServerThread(serverProtocol, server);
        serverThread.start();

        Exception clientFailure = null;
        try
        {
            clientProtocol.connect(client);

            OutputStream output = clientProtocol.getOutputStream();
            output.write(new byte[]{ '!' });

            byte[] echo = new byte[1];
            Streams.readFully(clientProtocol.getInputStream(), echo);
            assertEquals('!', echo[0]);

            output.close();
        }
        catch (Exception e)
        {
            clientFailure = e;
        }

        client.failure = clientFailure;

        serverThread.join();

        /*
         * Only where the client leg failed too: the server sees the pipe close under it once the
         * client is done, which is expected and says nothing. Where the handshake did fail, the
         * server's exception is the informative one - the alert the client received says only
         * "internal_error".
         */
        if (null != clientFailure)
        {
            throw null != serverThread.failure ? serverThread.failure : clientFailure;
        }

        assertNotNull("no server Certificate message was seen", client.certificateEntryList);
    }

    /**
     * The marker the response in this status carries, or null where there is no status. The statuses
     * read back per certificate are always of type ocsp, a single response.
     */
    private static String getMarker(CertificateStatus certificateStatus)
    {
        if (null == certificateStatus)
        {
            return null;
        }

        assertEquals(CertificateStatusType.ocsp, certificateStatus.getStatusType());

        return Strings.fromByteArray(
            certificateStatus.getOCSPResponse().getResponseBytes().getResponse().getOctets());
    }

    /**
     * The marker the entry's staple carries, or null if it carries no staple. Decodes the RFC 6066
     * CertificateStatus by hand - a one-byte status type then the DER response in a 24-bit length
     * field - rather than through CertificateStatus.parse, which wants a TlsContext this test has no
     * handle on.
     */
    private static String getStapledMarker(CertificateEntry certificateEntry)
        throws IOException
    {
        Hashtable extensions = certificateEntry.getExtensions();
        if (null == extensions)
        {
            return null;
        }

        byte[] extensionData = (byte[])extensions.get(TlsExtensionsUtils.EXT_status_request);
        if (null == extensionData)
        {
            return null;
        }

        assertTrue(extensionData.length > 4);
        assertEquals(CertificateStatusType.ocsp, extensionData[0] & 0xFF);

        int length = ((extensionData[1] & 0xFF) << 16) | ((extensionData[2] & 0xFF) << 8)
            | (extensionData[3] & 0xFF);
        assertEquals(extensionData.length - 4, length);

        OCSPResponse ocspResponse = OCSPResponse.getInstance(
            Arrays.copyOfRange(extensionData, 4, extensionData.length));

        return Strings.fromByteArray(ocspResponse.getResponseBytes().getResponse().getOctets());
    }

    /**
     * A response whose only distinguishing feature is the marker in its responseBytes: nothing in the
     * stapling path looks inside a response - verifying one is the receiving client's part - so this
     * is enough to tell which entry got which.
     */
    private static OCSPResponse ocspResponse(String marker)
    {
        return new OCSPResponse(new OCSPResponseStatus(OCSPResponseStatus.SUCCESSFUL),
            new ResponseBytes(OCSPObjectIdentifiers.id_pkix_ocsp_basic,
                new DEROctetString(Strings.toByteArray(marker))));
    }

    private static CertificateStatus ocspSingle(String marker)
    {
        return new CertificateStatus(CertificateStatusType.ocsp, ocspResponse(marker));
    }

    private static CertificateStatus ocspMulti(OCSPResponse endEntity, OCSPResponse intermediate)
    {
        Vector ocspResponseList = new Vector();
        ocspResponseList.addElement(endEntity);
        ocspResponseList.addElement(intermediate);

        return new CertificateStatus(CertificateStatusType.ocsp_multi, ocspResponseList);
    }

    /**
     * The test end-entity certificate reissued by the test CA with an RFC 7633 TLS feature extension
     * listing <code>tlsFeatures</code>, and otherwise unchanged - the same key, so it still pairs with
     * KEY_RESOURCE.
     */
    private static TlsCertificate createEndEntityWithTlsFeatures(TlsCrypto crypto, int[] tlsFeatures)
        throws IOException
    {
        ASN1EncodableVector tlsFeaturesVector = new ASN1EncodableVector(tlsFeatures.length);
        for (int i = 0; i < tlsFeatures.length; ++i)
        {
            tlsFeaturesVector.add(new ASN1Integer(tlsFeatures[i]));
        }

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
            new X509CertificateHolder(TlsTestUtils.loadBcCertificateResource(CERT_CHAIN[0])));
        builder.addExtension(TlsObjectIdentifiers.id_pe_tlsfeature, false, new DERSequence(tlsFeaturesVector));

        AsymmetricKeyParameter caPrivateKey = TlsTestUtils.loadBcPrivateKeyResource(CA_KEY_RESOURCE);

        ContentSigner contentSigner;
        try
        {
            AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA");
            AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

            contentSigner = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(caPrivateKey);
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }

        return crypto.createCertificate(builder.build(contentSigner).getEncoded());
    }

    private static Certificate replaceEndEntity(Certificate certificate, TlsCertificate endEntity)
    {
        CertificateEntry[] certificateEntryList = certificate.getCertificateEntryList();

        certificateEntryList[0] = new CertificateEntry(endEntity, certificateEntryList[0].getExtensions());

        return new Certificate(certificate.getCertificateRequestContext(), certificateEntryList);
    }

    private static Certificate addStatusRequest(Certificate certificate, int index, OCSPResponse ocspResponse)
        throws IOException
    {
        return addExtensionData(certificate, index, TlsExtensionsUtils.createStatusRequestExtension13(
            new CertificateStatus(CertificateStatusType.ocsp, ocspResponse)));
    }

    private static Certificate addExtensionData(Certificate certificate, int index, byte[] extensionData)
        throws IOException
    {
        CertificateEntry[] certificateEntryList = certificate.getCertificateEntryList();

        Hashtable extensions = new Hashtable();
        extensions.put(TlsExtensionsUtils.EXT_status_request, extensionData);

        certificateEntryList[index] = new CertificateEntry(
            certificateEntryList[index].getCertificate(), extensions);

        return new Certificate(certificate.getCertificateRequestContext(), certificateEntryList);
    }

    /**
     * Unlike {@code TlsProtocolTest.ServerThread}, this keeps whatever the server failed with:
     * the alert the client sees carries no detail, so a swallowed server-side exception leaves a
     * failure here impossible to read.
     */
    private static class ServerThread
        extends Thread
    {
        private final TlsServerProtocol serverProtocol;
        private final StatusStaplingTlsServer server;

        Exception failure = null;

        ServerThread(TlsServerProtocol serverProtocol, StatusStaplingTlsServer server)
        {
            this.serverProtocol = serverProtocol;
            this.server = server;
        }

        public void run()
        {
            try
            {
                serverProtocol.accept(server);
                Streams.pipeAll(serverProtocol.getInputStream(), serverProtocol.getOutputStream());
                serverProtocol.close();
            }
            catch (Exception e)
            {
                failure = e;
            }
        }
    }

    private static class CapturingTlsClient
        extends DefaultTlsClient
    {
        private final boolean requestStatus;

        ProtocolVersion[] supportedVersions = ProtocolVersion.TLSv13.only();

        /**
         * Have the client also offer "status_request_v2" (RFC 6961), where it offers TLS 1.2.
         */
        boolean requestMultiCertStatus = false;

        CertificateEntry[] certificateEntryList = null;
        ProtocolVersion negotiatedVersion = null;
        TlsServerCertificate serverCertificate = null;

        /**
         * Whatever the client leg of the handshake failed with, for a case where that is the
         * informative one - see the rethrow in {@link Tls13CertificateStatusTest#runHandshake}.
         */
        Exception failure = null;

        CapturingTlsClient(boolean requestStatus)
        {
            super(new BcTlsCrypto());

            this.requestStatus = requestStatus;
        }

        protected ProtocolVersion[] getSupportedVersions()
        {
            return supportedVersions;
        }

        protected CertificateStatusRequest getCertificateStatusRequest()
        {
            return requestStatus ? super.getCertificateStatusRequest() : null;
        }

        protected Vector getMultiCertStatusRequest()
        {
            if (!requestMultiCertStatus)
            {
                return null;
            }

            Vector statusRequestV2 = new Vector();
            statusRequestV2.addElement(new CertificateStatusRequestItemV2(CertificateStatusType.ocsp_multi,
                new OCSPStatusRequest(null, null)));
            return statusRequestV2;
        }

        public void notifyServerVersion(ProtocolVersion serverVersion)
            throws IOException
        {
            super.notifyServerVersion(serverVersion);

            this.negotiatedVersion = serverVersion;
        }

        public TlsAuthentication getAuthentication()
        {
            return new TlsAuthentication()
            {
                public void notifyServerCertificate(TlsServerCertificate serverCertificate)
                {
                    CapturingTlsClient.this.serverCertificate = serverCertificate;
                    certificateEntryList = serverCertificate.getCertificate().getCertificateEntryList();
                }

                public TlsCredentials getClientCredentials(CertificateRequest certificateRequest)
                {
                    return null;
                }
            };
        }
    }

    /**
     * Serves a two certificate chain, so that a positional list of responses has more than one entry
     * to be spread over.
     */
    private static class StatusStaplingTlsServer
        extends MockTlsServer
    {
        private final CertificateStatus certificateStatus;
        private final boolean attachToSecondEntry;
        private final byte[] malformedExtension;

        ProtocolVersion[] supportedVersions = ProtocolVersion.TLSv13.only();

        /**
         * TLS features for the end-entity certificate to list (see RFC 7633), or null to serve it
         * unchanged.
         */
        int[] tlsFeatures = null;

        /**
         * Answer "status_request_v2" (RFC 6961) where the client offers it.
         */
        boolean multiCertStatus = false;

        StatusStaplingTlsServer(CertificateStatus certificateStatus, boolean attachToSecondEntry,
            byte[] malformedExtension)
        {
            this.certificateStatus = certificateStatus;
            this.attachToSecondEntry = attachToSecondEntry;
            this.malformedExtension = malformedExtension;
        }

        protected ProtocolVersion[] getSupportedVersions()
        {
            return supportedVersions;
        }

        protected boolean allowMultiCertStatus()
        {
            return multiCertStatus;
        }

        public TlsCredentials getCredentials()
            throws IOException
        {
            SignatureAndHashAlgorithm signatureAndHashAlgorithm = selectRSASignatureAndHashAlgorithm();

            Certificate certificate = TlsTestUtils.loadCertificateChain(context, CERT_CHAIN);
            if (null != tlsFeatures)
            {
                certificate = replaceEndEntity(certificate,
                    createEndEntityWithTlsFeatures(context.getCrypto(), tlsFeatures));
            }
            if (attachToSecondEntry)
            {
                certificate = addStatusRequest(certificate, 1, ocspResponse("attached-by-server"));
            }
            if (null != malformedExtension)
            {
                certificate = addExtensionData(certificate, 0, malformedExtension);
            }

            AsymmetricKeyParameter privateKey = TlsTestUtils.loadBcPrivateKeyResource(KEY_RESOURCE);

            return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(context),
                (BcTlsCrypto)context.getCrypto(), privateKey, certificate, signatureAndHashAlgorithm);
        }

        public CertificateStatus getCertificateStatus()
            throws IOException
        {
            return certificateStatus;
        }

        private SignatureAndHashAlgorithm selectRSASignatureAndHashAlgorithm()
        {
            Vector supportedSignatureAlgorithms = context.getSecurityParametersHandshake().getClientSigAlgs();
            if (null == supportedSignatureAlgorithms)
            {
                supportedSignatureAlgorithms = TlsUtils.getDefaultSignatureAlgorithms(SignatureAlgorithm.rsa);
            }

            for (int i = 0; i < supportedSignatureAlgorithms.size(); ++i)
            {
                SignatureAndHashAlgorithm alg = (SignatureAndHashAlgorithm)
                    supportedSignatureAlgorithms.elementAt(i);

                if (SignatureAlgorithm.rsa == alg.getSignature())
                {
                    return alg;
                }
            }

            return null;
        }
    }
}
