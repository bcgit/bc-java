package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.Hashtable;
import java.util.Vector;

import junit.framework.TestCase;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateEntry;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.CertificateStatus;
import org.bouncycastle.tls.CertificateStatusType;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsCredentialedSigner;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.tls.TlsUtils;
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
 */
public class Tls13CertificateStatusTest
    extends TestCase
{
    private static final String[] CERT_CHAIN = new String[]{ "x509-server-rsa-sign.pem", "x509-ca-rsa.pem" };
    private static final String KEY_RESOURCE = "x509-server-key-rsa-sign.pem";

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
     * @param attachToSecondEntry have the server attach a staple of its own to the second entry of
     *                            the Certificate its credentials supply.
     * @return the CertificateEntry list the client received.
     */
    private CertificateEntry[] runHandshake(CertificateStatus certificateStatus, boolean attachToSecondEntry)
        throws Exception
    {
        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        CapturingTlsClient client = new CapturingTlsClient();
        StatusStaplingTlsServer server = new StatusStaplingTlsServer(certificateStatus, attachToSecondEntry);

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

        return client.certificateEntryList;
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

    private static Certificate addStatusRequest(Certificate certificate, int index, OCSPResponse ocspResponse)
        throws IOException
    {
        CertificateEntry[] certificateEntryList = certificate.getCertificateEntryList();

        Hashtable extensions = new Hashtable();
        extensions.put(TlsExtensionsUtils.EXT_status_request, TlsExtensionsUtils.createStatusRequestExtension13(
            new CertificateStatus(CertificateStatusType.ocsp, ocspResponse)));

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
        CertificateEntry[] certificateEntryList = null;

        CapturingTlsClient()
        {
            super(new BcTlsCrypto());
        }

        protected ProtocolVersion[] getSupportedVersions()
        {
            return ProtocolVersion.TLSv13.only();
        }

        public TlsAuthentication getAuthentication()
        {
            return new TlsAuthentication()
            {
                public void notifyServerCertificate(TlsServerCertificate serverCertificate)
                {
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

        StatusStaplingTlsServer(CertificateStatus certificateStatus, boolean attachToSecondEntry)
        {
            this.certificateStatus = certificateStatus;
            this.attachToSecondEntry = attachToSecondEntry;
        }

        protected ProtocolVersion[] getSupportedVersions()
        {
            return ProtocolVersion.TLSv13.only();
        }

        public TlsCredentials getCredentials()
            throws IOException
        {
            SignatureAndHashAlgorithm signatureAndHashAlgorithm = selectRSASignatureAndHashAlgorithm();

            Certificate certificate = TlsTestUtils.loadCertificateChain(context, CERT_CHAIN);
            if (attachToSecondEntry)
            {
                certificate = addStatusRequest(certificate, 1, ocspResponse("attached-by-server"));
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
