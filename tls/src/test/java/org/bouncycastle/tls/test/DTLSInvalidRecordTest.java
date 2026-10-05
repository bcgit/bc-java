package org.bouncycastle.tls.test;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ContentType;
import org.bouncycastle.tls.DTLSClientProtocol;
import org.bouncycastle.tls.DTLSServerProtocol;
import org.bouncycastle.tls.DTLSTransport;
import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsServer;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.util.Arrays;

import junit.framework.TestCase;

/**
 * RFC 9147 4.5.2 / RFC 6347 4.1.2.7: invalid DTLS records SHOULD be silently discarded, preserving the
 * association. A forged record whose body is too short for the cipher (decode_error), or not a whole number of
 * blocks (decryption_failed), must be dropped just like one whose MAC fails (bad_record_mac), rather than
 * tearing the connection down with a fatal alert. This test establishes a loopback DTLS association, injects
 * such records from off-path towards each peer, and checks that application data still flows.
 */
public class DTLSInvalidRecordTest
    extends TestCase
{
    private static final int RECORD_HEADER_LENGTH = FilteredDatagramTransport.RECORD_HEADER_LENGTH;

    public void testAEADCipherInvalidRecordsDiscarded() throws Exception
    {
        /*
         * ChaCha20-Poly1305: 16 byte tag, no explicit nonce. A 2 byte body is below the decode limit
         * (decode_error); a 40 byte body reaches the AEAD, whose tag check fails (bad_record_mac).
         */
        implTestInvalidRecordsDiscarded(CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256, new int[]{ 2, 40 });
    }

    public void testBlockCipherInvalidRecordsDiscarded() throws Exception
    {
        /*
         * AES-128-CBC with HMAC-SHA256: 16 byte explicit IV, 16 byte blocks, 32 byte MAC. A 2 byte body is
         * below the minimum length (decode_error); 65 bytes is above the minimum but not a whole number of
         * blocks, with or without encrypt-then-MAC (decryption_failed); 80 bytes decrypts and then fails the
         * MAC or padding check (bad_record_mac).
         */
        implTestInvalidRecordsDiscarded(CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, new int[]{ 2, 65, 80 });
    }

    private void implTestInvalidRecordsDiscarded(final int cipherSuite, int[] forgedBodyLengths) throws Exception
    {
        MockPSKDTLSClient client = new MockPSKDTLSClient(null)
        {
            protected int[] getSupportedCipherSuites()
            {
                return TlsUtils.getSupportedCipherSuites(getCrypto(), new int[]{ cipherSuite });
            }
        };
        MockPSKDTLSServer server = new MockPSKDTLSServer();

        DTLSClientProtocol clientProtocol = new DTLSClientProtocol();
        DTLSServerProtocol serverProtocol = new DTLSServerProtocol();

        MockDatagramAssociation network = new MockDatagramAssociation(1500);

        // Keep the raw transports: sending on one delivers a datagram to the other peer's receive queue.
        DatagramTransport clientTransport = network.getClient();
        DatagramTransport serverTransport = network.getServer();

        ServerThread serverThread = new ServerThread(serverProtocol, server, serverTransport);
        serverThread.start();

        DTLSTransport dtlsClient = clientProtocol.connect(client, clientTransport);

        SecureRandom random = client.getCrypto().getSecureRandom();

        try
        {
            // Confirm the association is up and carrying application data.
            implEcho(dtlsClient, 1);

            // A sequence number well ahead of the replay window, so that each forgery is 'fresh'.
            long forgedSeq = 1L << 40;

            for (int i = 0; i < forgedBodyLengths.length; ++i)
            {
                int bodyLength = forgedBodyLengths[i];

                // Off-path forgery towards the server (delivered by sending on the client's raw transport).
                byte[] toServer = createForgedRecord(random, forgedSeq++, bodyLength);
                clientTransport.send(toServer, 0, toServer.length);

                // Off-path forgery towards the client.
                byte[] toClient = createForgedRecord(random, forgedSeq++, bodyLength);
                serverTransport.send(toClient, 0, toClient.length);

                // Both peers must have discarded the forgery and still be able to exchange application data.
                implEcho(dtlsClient, i + 2);
            }
        }
        finally
        {
            dtlsClient.close();
            serverThread.shutdown();
        }

        assertNull("Server failed after forged record: " + serverThread.getFailure(), serverThread.getFailure());
    }

    private static byte[] createForgedRecord(SecureRandom random, long seq, int bodyLength)
    {
        byte[] record = new byte[RECORD_HEADER_LENGTH + bodyLength];
        record[0] = (byte)ContentType.application_data;
        TlsUtils.writeVersion(ProtocolVersion.DTLSv12, record, 1);
        TlsUtils.writeUint16(1, record, 3);
        TlsUtils.writeUint48(seq, record, 5);
        TlsUtils.writeUint16(bodyLength, record, 11);
        byte[] body = new byte[bodyLength];
        random.nextBytes(body);
        System.arraycopy(body, 0, record, RECORD_HEADER_LENGTH, bodyLength);
        return record;
    }

    private static void implEcho(DTLSTransport dtlsClient, int length) throws IOException
    {
        byte[] data = new byte[length];
        Arrays.fill(data, (byte)length);
        dtlsClient.send(data, 0, data.length);

        byte[] buf = new byte[dtlsClient.getReceiveLimit()];
        for (int attempt = 0; attempt < 10; ++attempt)
        {
            int received = dtlsClient.receive(buf, 0, buf.length, 500);
            if (received >= 0)
            {
                assertTrue("Echo mismatch", Arrays.areEqual(data, Arrays.copyOf(buf, received)));
                return;
            }
        }
        fail("No echo received from server");
    }

    static class ServerThread
        extends Thread
    {
        private final DTLSServerProtocol serverProtocol;
        private final TlsServer server;
        private final DatagramTransport serverTransport;
        private volatile boolean isShutdown = false;
        private volatile Exception failure = null;

        ServerThread(DTLSServerProtocol serverProtocol, TlsServer server, DatagramTransport serverTransport)
        {
            this.serverProtocol = serverProtocol;
            this.server = server;
            this.serverTransport = serverTransport;
        }

        Exception getFailure()
        {
            return failure;
        }

        public void run()
        {
            try
            {
                DTLSTransport dtlsServer = serverProtocol.accept(server, serverTransport);
                byte[] buf = new byte[dtlsServer.getReceiveLimit()];
                while (!isShutdown)
                {
                    int length = dtlsServer.receive(buf, 0, buf.length, 100);
                    if (length >= 0)
                    {
                        dtlsServer.send(buf, 0, length);
                    }
                }
                dtlsServer.close();
            }
            catch (Exception e)
            {
                failure = e;
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
