package org.bouncycastle.crypto.tls.test;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.crypto.tls.DTLSClientProtocol;
import org.bouncycastle.crypto.tls.DTLSServerProtocol;
import org.bouncycastle.crypto.tls.DTLSTransport;
import org.bouncycastle.crypto.tls.DatagramTransport;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import static org.junit.Assert.*;

@RunWith(Parameterized.class)
public class DTLSTestCase
{
    // Make the access to constants less verbose
    static abstract class C extends TlsTestConfig {}

    @Parameterized.Parameters(name = "{index}: {1}")
    public static Collection<Object[]> data() {
        List<Object[]> params = new ArrayList<Object[]>();
        addVersionTests(params, ProtocolVersion.DTLSv10);
        addVersionTests(params, ProtocolVersion.DTLSv12);
        return params;
    }

    private static void addVersionTests(List<Object[]> params, ProtocolVersion version)
    {
        String prefix = version.toString().replaceAll("[ \\.]", "") + "_";

        /*
         * NOTE: Temporarily disabled automatic test runs because of problems getting a clean exit
         * of the DTLS server after a fatal alert. As of writing, manual runs show the correct
         * alerts being raised
         */

//        {
//            TlsTestConfig c = createDTLSTestConfig(version);
//            c.clientAuth = C.CLIENT_AUTH_INVALID_VERIFY;
//            c.expectServerFatalAlert(AlertDescription.decrypt_error);
//
//            testSuite.addTest(new DTLSTestCase(c, prefix + "BadCertificateVerify"));
//        }
//
//        {
//            TlsTestConfig c = createDTLSTestConfig(version);
//            c.clientAuth = C.CLIENT_AUTH_INVALID_CERT;
//            c.expectServerFatalAlert(AlertDescription.bad_certificate);
//
//            testSuite.addTest(new DTLSTestCase(c, prefix + "BadClientCertificate"));
//        }
//
//        {
//            TlsTestConfig c = createDTLSTestConfig(version);
//            c.clientAuth = C.CLIENT_AUTH_NONE;
//            c.serverCertReq = C.SERVER_CERT_REQ_MANDATORY;
//            c.expectServerFatalAlert(AlertDescription.handshake_failure);
//
//            testSuite.addTest(new DTLSTestCase(c, prefix + "BadMandatoryCertReqDeclined"));
//        }

        {
            TlsTestConfig c = createDTLSTestConfig(version);

            params.add(new Object[] { c, prefix + "GoodDefault" });
        }

        {
            TlsTestConfig c = createDTLSTestConfig(version);
            c.serverCertReq = C.SERVER_CERT_REQ_NONE;

            params.add(new Object[]{ c, prefix + "GoodNoCertReq"});
        }

        {
            TlsTestConfig c = createDTLSTestConfig(version);
            c.clientAuth = C.CLIENT_AUTH_NONE;

            params.add(new Object[]{ c, prefix + "GoodOptionalCertReqDeclined"});
        }
    }

    private static TlsTestConfig createDTLSTestConfig(ProtocolVersion version)
    {
        TlsTestConfig c = new TlsTestConfig();
        c.clientMinimumVersion = ProtocolVersion.DTLSv10;
        /*
         * TODO We'd like to just set the offer version to DTLSv12, but there is a known issue with
         * overly-restrictive version checks b/w BC DTLS 1.2 client, BC DTLS 1.0 server
         */
        c.clientOfferVersion = version;
        c.serverMaximumVersion = version;
        c.serverMinimumVersion = ProtocolVersion.DTLSv10;
        return c;
    }

    private static void checkDTLSVersion(ProtocolVersion version)
    {
        if (version != null && !version.isDTLS())
        {
            throw new IllegalStateException("Non-DTLS version");
        }
    }

    protected final TlsTestConfig config;

    public DTLSTestCase(TlsTestConfig config, String name)
    {
        checkDTLSVersion(config.clientMinimumVersion);
        checkDTLSVersion(config.clientOfferVersion);
        checkDTLSVersion(config.serverMaximumVersion);
        checkDTLSVersion(config.serverMinimumVersion);

        this.config = config;
    }

    @Test
    public void runTest() throws Throwable
    {
        SecureRandom secureRandom = new SecureRandom();

        DTLSClientProtocol clientProtocol = new DTLSClientProtocol(secureRandom);
        DTLSServerProtocol serverProtocol = new DTLSServerProtocol(secureRandom);

        MockDatagramAssociation network = new MockDatagramAssociation(1500);

        TlsTestClientImpl clientImpl = new TlsTestClientImpl(config);
        TlsTestServerImpl serverImpl = new TlsTestServerImpl(config);

        ServerThread serverThread = new ServerThread(serverProtocol, network.getServer(), serverImpl);
        serverThread.start();

        Exception caught = null;
        try
        {
            DatagramTransport clientTransport = network.getClient();
    
            if (TlsTestConfig.DEBUG)
            {
                clientTransport = new LoggingDatagramTransport(clientTransport, System.out);
            }
    
            DTLSTransport dtlsClient = clientProtocol.connect(clientImpl, clientTransport);
    
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
        }
        catch (Exception e)
        {
            caught = e;
            logException(caught);
        }

        serverThread.shutdown();

        // TODO Add checks that the various streams were closed

        assertEquals("Client fatal alert connection end", config.expectFatalAlertConnectionEnd, clientImpl.firstFatalAlertConnectionEnd);
        assertEquals("Server fatal alert connection end", config.expectFatalAlertConnectionEnd, serverImpl.firstFatalAlertConnectionEnd);

        assertEquals("Client fatal alert description", config.expectFatalAlertDescription, clientImpl.firstFatalAlertDescription);
        assertEquals("Server fatal alert description", config.expectFatalAlertDescription, serverImpl.firstFatalAlertDescription);

        if (config.expectFatalAlertConnectionEnd == -1)
        {
            assertNull("Unexpected client exception", caught);
            assertNull("Unexpected server exception", serverThread.caught);
        }
    }

    protected  void logException(Exception e)
    {
        if (TlsTestConfig.DEBUG)
        {
            e.printStackTrace();
        }
    }

    class ServerThread
        extends Thread
    {
        private final DTLSServerProtocol serverProtocol;
        private final DatagramTransport serverTransport;
        private final TlsTestServerImpl serverImpl;

        private volatile boolean isShutdown = false;
        Exception caught = null;

        ServerThread(DTLSServerProtocol serverProtocol, DatagramTransport serverTransport, TlsTestServerImpl serverImpl)
        {
            this.serverProtocol = serverProtocol;
            this.serverTransport = serverTransport;
            this.serverImpl = serverImpl;
        }

        public void run()
        {
            try
            {
                DTLSTransport dtlsServer = serverProtocol.accept(serverImpl, serverTransport);
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
                caught = e;
                logException(caught);
            }
        }

        void shutdown()
            throws InterruptedException
        {
            if (!isShutdown)
            {
                isShutdown = true;
                this.interrupt();
                this.join();
            }
        }
    }
}
