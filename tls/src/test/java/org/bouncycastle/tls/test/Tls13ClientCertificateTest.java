package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.Hashtable;

import junit.framework.TestCase;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateEntry;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.CertificateStatus;
import org.bouncycastle.tls.CertificateStatusType;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

/**
 * What a TLS 1.3 server requires of the client's Certificate message beyond the certificates
 * themselves (RFC 8446 sec. 4.4.2): the certificate_request_context of the CertificateRequest it
 * answers, and extensions that correspond to ones in that CertificateRequest.
 */
public class Tls13ClientCertificateTest
    extends TestCase
{
    private static final String[] CLIENT_CERT_CHAIN = new String[]{ "x509-client-rsa.pem" };
    private static final String CLIENT_KEY_RESOURCE = "x509-client-key-rsa.pem";

    public void testPlainClientCertificateIsAccepted()
        throws Exception
    {
        ClientCertificateTlsClient client = new ClientCertificateTlsClient(TlsUtils.EMPTY_BYTES, null);
        Tls13Server server = new Tls13Server();

        Exception serverFailure = runHandshake(client, server);
        assertNull("server failed with " + serverFailure, serverFailure);

        assertEquals(ProtocolVersion.TLSv13, client.negotiatedVersion);
        assertNotNull("the server saw no client Certificate", server.clientCertificate);
        assertEquals(1, server.clientCertificate.getLength());
    }

    /**
     * RFC 8446 sec. 4.4.2: a Certificate answering a CertificateRequest carries that
     * CertificateRequest's certificate_request_context, which is empty for one sent during the
     * handshake.
     */
    public void testMismatchedCertificateRequestContextIsRejected()
        throws Exception
    {
        ClientCertificateTlsClient client = new ClientCertificateTlsClient(new byte[]{ 0x01 }, null);

        Exception serverFailure = runHandshake(client, new Tls13Server());

        assertServerFailedWith(serverFailure, AlertDescription.illegal_parameter);
    }

    /**
     * RFC 8446 sec. 4.4.2: extensions in a client's Certificate must correspond to ones in the
     * CertificateRequest, and this server's asks for no staple.
     */
    public void testUnrequestedEntryExtensionIsRejected()
        throws Exception
    {
        byte[] extensionData = TlsExtensionsUtils.createStatusRequestExtension13(
            new CertificateStatus(CertificateStatusType.ocsp, createOcspResponse()));

        Hashtable endEntityExtensions = new Hashtable();
        endEntityExtensions.put(TlsExtensionsUtils.EXT_status_request, extensionData);

        ClientCertificateTlsClient client = new ClientCertificateTlsClient(TlsUtils.EMPTY_BYTES,
            endEntityExtensions);

        Exception serverFailure = runHandshake(client, new Tls13Server());

        assertServerFailedWith(serverFailure, AlertDescription.unsupported_extension);
    }

    private static void assertServerFailedWith(Exception serverFailure, short alertDescription)
    {
        assertTrue("server failed with " + serverFailure, serverFailure instanceof TlsFatalAlert);
        assertEquals(alertDescription, ((TlsFatalAlert)serverFailure).getAlertDescription());
    }

    /**
     * @return whatever the server leg of the handshake failed with, where the client leg failed too;
     *         null where the client leg succeeded. A failure of the client leg alone is rethrown.
     */
    private static Exception runHandshake(ClientCertificateTlsClient client, Tls13Server server)
        throws Exception
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

        serverThread.join();

        /*
         * Only where the client leg failed too: the server sees the pipe close under it once the
         * client is done, which is expected and says nothing.
         */
        if (null == clientFailure)
        {
            return null;
        }
        if (null == serverThread.failure)
        {
            throw clientFailure;
        }
        return serverThread.failure;
    }

    private static OCSPResponse createOcspResponse()
    {
        return new OCSPResponse(new OCSPResponseStatus(OCSPResponseStatus.SUCCESSFUL),
            new ResponseBytes(OCSPObjectIdentifiers.id_pkix_ocsp_basic,
                new DEROctetString(Strings.toByteArray("client-staple"))));
    }

    private static class ServerThread
        extends Thread
    {
        private final TlsServerProtocol serverProtocol;
        private final Tls13Server server;

        Exception failure = null;

        ServerThread(TlsServerProtocol serverProtocol, Tls13Server server)
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

    /**
     * Answers the server's CertificateRequest with the RSA test client certificate, sent with the
     * given certificate_request_context and extensions on its (only) CertificateEntry.
     */
    private static class ClientCertificateTlsClient
        extends MockTlsClient
    {
        private final byte[] certificateRequestContext;
        private final Hashtable endEntityExtensions;

        ProtocolVersion negotiatedVersion = null;

        ClientCertificateTlsClient(byte[] certificateRequestContext, Hashtable endEntityExtensions)
        {
            super(null);

            this.certificateRequestContext = certificateRequestContext;
            this.endEntityExtensions = endEntityExtensions;
        }

        protected ProtocolVersion[] getSupportedVersions()
        {
            return ProtocolVersion.TLSv13.only();
        }

        public void notifyServerVersion(ProtocolVersion serverVersion)
            throws IOException
        {
            super.notifyServerVersion(serverVersion);

            this.negotiatedVersion = serverVersion;
        }

        public TlsAuthentication getAuthentication()
            throws IOException
        {
            final TlsAuthentication authentication = super.getAuthentication();

            return new TlsAuthentication()
            {
                public void notifyServerCertificate(TlsServerCertificate serverCertificate)
                    throws IOException
                {
                    authentication.notifyServerCertificate(serverCertificate);
                }

                public TlsCredentials getClientCredentials(CertificateRequest certificateRequest)
                    throws IOException
                {
                    return selectClientCredentials();
                }
            };
        }

        private TlsCredentials selectClientCredentials()
            throws IOException
        {
            CertificateEntry[] certificateEntryList = TlsTestUtils.loadCertificateChain(context,
                CLIENT_CERT_CHAIN).getCertificateEntryList();

            certificateEntryList[0] = new CertificateEntry(certificateEntryList[0].getCertificate(),
                endEntityExtensions);

            Certificate certificate = new Certificate(certificateRequestContext, certificateEntryList);

            AsymmetricKeyParameter privateKey = TlsTestUtils.loadBcPrivateKeyResource(CLIENT_KEY_RESOURCE);

            return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(context),
                (BcTlsCrypto)context.getCrypto(), privateKey, certificate,
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha256);
        }
    }

    /**
     * A TLS 1.3 only server that keeps the client Certificate it accepted.
     */
    private static class Tls13Server
        extends MockTlsServer
    {
        Certificate clientCertificate = null;

        protected ProtocolVersion[] getSupportedVersions()
        {
            return ProtocolVersion.TLSv13.only();
        }

        public void notifyClientCertificate(Certificate clientCertificate)
            throws IOException
        {
            super.notifyClientCertificate(clientCertificate);

            this.clientCertificate = clientCertificate;
        }
    }
}
