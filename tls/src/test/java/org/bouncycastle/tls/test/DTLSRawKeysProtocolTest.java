package org.bouncycastle.tls.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.tls.CertificateType;
import org.bouncycastle.tls.DTLSClientProtocol;
import org.bouncycastle.tls.DTLSRequest;
import org.bouncycastle.tls.DTLSServerProtocol;
import org.bouncycastle.tls.DTLSTransport;
import org.bouncycastle.tls.DTLSVerifier;
import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsClient;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsServer;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

import junit.framework.TestCase;

public class DTLSRawKeysProtocolTest
    extends TestCase
{
    private final SecureRandom RANDOM = new SecureRandom();

    public void testClientSendsExtensionButServerDoesNotSupportIt() throws Exception
    {
        testClientSendsExtensionButServerDoesNotSupportIt(ProtocolVersion.DTLSv12);
    }

    // TODO[dtls13]
//    public void testClientSendsExtensionButServerDoesNotSupportIt_13() throws Exception
//    {
//        testClientSendsExtensionButServerDoesNotSupportIt(ProtocolVersion.DTLSv13);
//    }

    private void testClientSendsExtensionButServerDoesNotSupportIt(ProtocolVersion tlsVersion) throws Exception
    {
        MockRawKeysTlsClient client = new MockRawKeysTlsClient(
                CertificateType.X509,
                (short) -1,
                new short[] {CertificateType.RawPublicKey, CertificateType.X509},
                null,
                generateKeyPair(),
                tlsVersion);
        MockRawKeysTlsServer server = new MockRawKeysTlsServer(
                CertificateType.X509,
                (short) -1,
                null,
                generateKeyPair(),
                tlsVersion);
        pumpData(client, server);
    }

    public void testExtensionsAreOmittedIfSpecifiedButOnlyContainX509() throws Exception
    {
        testExtensionsAreOmittedIfSpecifiedButOnlyContainX509(ProtocolVersion.DTLSv12);
    }

    // TODO[dtls13]
//    public void testExtensionsAreOmittedIfSpecifiedButOnlyContainX509_13() throws Exception
//    {
//        testExtensionsAreOmittedIfSpecifiedButOnlyContainX509(ProtocolVersion.DTLSv13);
//    }

    private void testExtensionsAreOmittedIfSpecifiedButOnlyContainX509(ProtocolVersion tlsVersion) throws Exception
    {
        MockRawKeysTlsClient client = new MockRawKeysTlsClient(
                CertificateType.X509,
                CertificateType.X509,
                new short[] {CertificateType.X509},
                new short[] {CertificateType.X509},
                generateKeyPair(),
                tlsVersion);
        MockRawKeysTlsServer server = new MockRawKeysTlsServer(
                CertificateType.X509,
                CertificateType.X509,
                new short[] {CertificateType.X509},
                generateKeyPair(),
                tlsVersion);
        pumpData(client, server);

        assertFalse(
                "client cert type extension should not be sent",
                server.receivedClientExtensions.containsKey(TlsExtensionsUtils.EXT_client_certificate_type));
        assertFalse(
                "server cert type extension should not be sent",
                server.receivedClientExtensions.containsKey(TlsExtensionsUtils.EXT_server_certificate_type));
    }

    public void testBothSidesUseRawKey() throws Exception
    {
        testBothSidesUseRawKey(ProtocolVersion.DTLSv12);
    }

    // TODO[dtls13]
//    public void testBothSidesUseRawKey_13() throws Exception
//    {
//        testBothSidesUseRawKey(ProtocolVersion.DTLSv13);
//    }

    private void testBothSidesUseRawKey(ProtocolVersion tlsVersion) throws Exception
    {
        MockRawKeysTlsClient client = new MockRawKeysTlsClient(
                CertificateType.RawPublicKey,
                CertificateType.RawPublicKey,
                new short[] {CertificateType.RawPublicKey},
                new short[] {CertificateType.RawPublicKey},
                generateKeyPair(),
                tlsVersion);
        MockRawKeysTlsServer server = new MockRawKeysTlsServer(
                CertificateType.RawPublicKey,
                CertificateType.RawPublicKey,
                new short[] {CertificateType.RawPublicKey},
                generateKeyPair(),
                tlsVersion);
        pumpData(client, server);
    }

    public void testServerUsesRawKeyAndClientIsAnonymous() throws Exception
    {
        testServerUsesRawKeyAndClientIsAnonymous(ProtocolVersion.DTLSv12);
    }

    // TODO[dtls13]
//    public void testServerUsesRawKeyAndClientIsAnonymous_13() throws Exception
//    {
//        testServerUsesRawKeyAndClientIsAnonymous(ProtocolVersion.DTLSv13);
//    }

    private void testServerUsesRawKeyAndClientIsAnonymous(ProtocolVersion tlsVersion) throws Exception
    {
        MockRawKeysTlsClient client = new MockRawKeysTlsClient(
                CertificateType.RawPublicKey,
                (short) -1,
                new short[] {CertificateType.RawPublicKey},
                null,
                generateKeyPair(),
                tlsVersion);
        MockRawKeysTlsServer server = new MockRawKeysTlsServer(
                CertificateType.RawPublicKey,
                (short) -1,
                null,
                generateKeyPair(),
                tlsVersion);
        pumpData(client, server);
    }

    public void testServerUsesRawKeyAndClientUsesX509() throws Exception
    {
        testServerUsesRawKeyAndClientUsesX509(ProtocolVersion.DTLSv12);
    }

    // TODO[dtls13]
//    public void testServerUsesRawKeyAndClientUsesX509_13() throws Exception
//    {
//        testServerUsesRawKeyAndClientUsesX509(ProtocolVersion.DTLSv13);
//    }

    private void testServerUsesRawKeyAndClientUsesX509(ProtocolVersion tlsVersion) throws Exception
    {
        MockRawKeysTlsClient client = new MockRawKeysTlsClient(
                CertificateType.RawPublicKey,
                CertificateType.X509,
                new short[] {CertificateType.RawPublicKey},
                null,
                generateKeyPair(),
                tlsVersion);
        MockRawKeysTlsServer server = new MockRawKeysTlsServer(
                CertificateType.RawPublicKey,
                CertificateType.X509,
                null,
                generateKeyPair(),
                tlsVersion);
        pumpData(client, server);
    }

    public void testServerUsesX509AndClientUsesRawKey() throws Exception
    {
        testServerUsesX509AndClientUsesRawKey(ProtocolVersion.DTLSv12);
    }

    // TODO[dtls13]
//    public void testServerUsesX509AndClientUsesRawKey_13() throws Exception
//    {
//        testServerUsesX509AndClientUsesRawKey(ProtocolVersion.DTLSv13);
//    }

    private void testServerUsesX509AndClientUsesRawKey(ProtocolVersion tlsVersion) throws Exception
    {
        MockRawKeysTlsClient client = new MockRawKeysTlsClient(
                CertificateType.X509,
                CertificateType.RawPublicKey,
                null,
                new short[] {CertificateType.RawPublicKey},
                generateKeyPair(),
                tlsVersion);
        MockRawKeysTlsServer server = new MockRawKeysTlsServer(
                CertificateType.X509,
                CertificateType.RawPublicKey,
                new short[] {CertificateType.RawPublicKey},
                generateKeyPair(),
                tlsVersion);
        pumpData(client, server);
    }

    // NOTE: Test disabled because of problems getting a clean exit of the DTLS server after a fatal alert.
/*
    public void testClientSendsClientCertExtensionButServerHasNoCommonTypes() throws Exception
    {
        testClientSendsClientCertExtensionButServerHasNoCommonTypes(ProtocolVersion.DTLSv12);
    }

    // TODO[dtls13]
//    public void testClientSendsClientCertExtensionButServerHasNoCommonTypes_13() throws Exception
//    {
//        testClientSendsClientCertExtensionButServerHasNoCommonTypes(ProtocolVersion.DTLSv13);
//    }

    private void testClientSendsClientCertExtensionButServerHasNoCommonTypes(ProtocolVersion tlsVersion) throws Exception
    {
        try
        {
            MockRawKeysTlsClient client = new MockRawKeysTlsClient(
                    CertificateType.X509,
                    CertificateType.RawPublicKey,
                    null,
                    new short[] {CertificateType.RawPublicKey},
                    generateKeyPair(),
                    tlsVersion);
            MockRawKeysTlsServer server = new MockRawKeysTlsServer(
                    CertificateType.X509,
                    CertificateType.X509,
                    new short[] {CertificateType.X509},
                    generateKeyPair(),
                    tlsVersion);
            pumpData(client, server);
            fail("Should have caused unsupported_certificate alert");
        }
        catch (TlsFatalAlertReceived alert)
        {
            assertEquals("Should have caused unsupported_certificate alert", alert.getAlertDescription(), AlertDescription.unsupported_certificate);
        }
    }
*/

    // NOTE: Test disabled because of problems getting a clean exit of the DTLS server after a fatal alert.
/*
    public void testClientSendsServerCertExtensionButServerHasNoCommonTypes() throws Exception
    {
        testClientSendsServerCertExtensionButServerHasNoCommonTypes(ProtocolVersion.DTLSv12);
    }

    // TODO[dtls13]
//    public void testClientSendsServerCertExtensionButServerHasNoCommonTypes_13() throws Exception
//    {
//        testClientSendsServerCertExtensionButServerHasNoCommonTypes(ProtocolVersion.DTLSv13);
//    }

    private void testClientSendsServerCertExtensionButServerHasNoCommonTypes(ProtocolVersion tlsVersion) throws Exception
    {
        try
        {
            MockRawKeysTlsClient client = new MockRawKeysTlsClient(
                    CertificateType.RawPublicKey,
                    CertificateType.RawPublicKey,
                    new short[] {CertificateType.RawPublicKey},
                    null,
                    generateKeyPair(),
                    tlsVersion);
            MockRawKeysTlsServer server = new MockRawKeysTlsServer(
                    CertificateType.X509,
                    CertificateType.RawPublicKey,
                    new short[] {CertificateType.RawPublicKey},
                    generateKeyPair(),
                    tlsVersion);
            pumpData(client, server);
            fail("Should have caused unsupported_certificate alert");
        }
        catch (TlsFatalAlertReceived alert)
        {
            assertEquals("Should have caused unsupported_certificate alert", alert.getAlertDescription(), AlertDescription.unsupported_certificate);
        }
    }
*/

    private Ed25519PrivateKeyParameters generateKeyPair()
    {
        return new Ed25519PrivateKeyParameters(RANDOM);
    }

    private void pumpData(TlsClient client, TlsServer server) throws Exception
    {
        DTLSClientProtocol clientProtocol = new DTLSClientProtocol();
        DTLSServerProtocol serverProtocol = new DTLSServerProtocol();

        MockDatagramAssociation network = new MockDatagramAssociation(1500);

        ServerThread serverThread = new ServerThread(serverProtocol, server, network.getServer());
        serverThread.start();

        DatagramTransport clientTransport = network.getClient();

        clientTransport = new UnreliableDatagramTransport(clientTransport, RANDOM, 0, 0);

        clientTransport = new LoggingDatagramTransport(clientTransport, System.out);

        DTLSTransport dtlsClient = clientProtocol.connect(client, clientTransport);

        for (int i = 1; i <= 10; ++i)
        {
            byte[] data = new byte[i];
            Arrays.fill(data, (byte)i);
            dtlsClient.send(data, 0, data.length);
        }

        byte[] buf = new byte[dtlsClient.getReceiveLimit()];
        while (dtlsClient.receive(buf, 0, buf.length, 100) >= 0)
        {
        }

        dtlsClient.close();

        serverThread.shutdown();
    }

    static class ServerThread
        extends Thread
    {
        private final DTLSServerProtocol serverProtocol;
        private final TlsServer server;
        private final DatagramTransport serverTransport;
        private volatile boolean isShutdown = false;

        ServerThread(DTLSServerProtocol serverProtocol, TlsServer server, DatagramTransport serverTransport)
        {
            this.serverProtocol = serverProtocol;
            this.server = server;
            this.serverTransport = serverTransport;
        }

        public void run()
        {
            try
            {
                TlsCrypto serverCrypto = server.getCrypto();

                DTLSRequest request = null;
    
                // Use DTLSVerifier to require a HelloVerifyRequest cookie exchange before accepting
                {
                    DTLSVerifier verifier = new DTLSVerifier(serverCrypto);
    
                    // NOTE: Test value only - would typically be the client IP address
                    byte[] clientID = Strings.toUTF8ByteArray("MockRawKeysTlsClient");
    
                    int receiveLimit = serverTransport.getReceiveLimit();
                    int dummyOffset = serverCrypto.getSecureRandom().nextInt(16) + 1;
                    byte[] buf = new byte[dummyOffset + serverTransport.getReceiveLimit()];
    
                    do
                    {
                        if (isShutdown)
                            return;
    
                        int length = serverTransport.receive(buf, dummyOffset, receiveLimit, 100);
                        if (length > 0)
                        {
                            request = verifier.verifyRequest(clientID, buf, dummyOffset, length, serverTransport);
                        }
                    }
                    while (request == null);
                }

                // NOTE: A real server would handle each DTLSRequest in a new task/thread and continue accepting
                {
                    DTLSTransport dtlsTransport = serverProtocol.accept(server, serverTransport, request);                
                    byte[] buf = new byte[dtlsTransport.getReceiveLimit()];
                    while (!isShutdown)
                    {
                        int length = dtlsTransport.receive(buf, 0, buf.length, 100);
                        if (length >= 0)
                        {
                            dtlsTransport.send(buf, 0, length);
                        }
                    }
                    dtlsTransport.close();
                }
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }

        void shutdown()
            throws InterruptedException
        {
            if (!isShutdown)
            {
                isShutdown = true;
                this.join();
            }
        }
    }
}
