package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import junit.framework.TestCase;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.Strings;

/**
 * The timeout {@link OcspStapleHttpFetcher} owes its caller. A fetch runs on a handshake thread, so
 * the responder at the other end must not be able to decide how long that thread is held - and a
 * read timeout alone does not achieve that, since it bounds each <code>read()</code> rather than the
 * exchange.
 * <p/>
 * Driven against a stub responder on a loopback socket, which is what lets a test be the kind of
 * responder no real one would be.
 */
public class OcspStapleHttpFetcherTest
    extends TestCase
{
    private static final int RESPONSE_TIMEOUT_MS = 500;

    private static long serialNumber = 0;

    private X509Certificate cert;

    protected void setUp()
        throws Exception
    {
        if (null == Security.getProvider(BouncyCastleProvider.PROVIDER_NAME))
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        X500Name caName = new X500Name("CN=Test CA");
        KeyPair caKeyPair = generateKeyPair();

        cert = buildCert(caName, caKeyPair.getPrivate(), new X500Name("CN=Test EE"),
            generateKeyPair().getPublic());
    }

    /**
     * "Wait indefinitely" is what setConnectTimeout(0) / setReadTimeout(0) mean, and it is not
     * something a handshake thread can be asked to do - so the fetcher refuses the value rather than
     * quietly holding the thread forever. {@link OcspStapleCache#create} enforces the same minimum
     * on the property that reaches here.
     */
    public void testResponseTimeoutMustBePositive()
    {
        try
        {
            new OcspStapleHttpFetcher(null, 0);
            fail("a zero response timeout should have been refused");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("'responseTimeoutMs' must be positive", e.getMessage());
        }

        try
        {
            new OcspStapleHttpFetcher(null, -1);
            fail("a negative response timeout should have been refused");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("'responseTimeoutMs' must be positive", e.getMessage());
        }
    }

    /**
     * A responder that answers, and then trickles the body a byte at a time, satisfies a per-read
     * timeout indefinitely - the read that would have timed out keeps being answered just in time.
     * The fetch is bounded anyway, by a deadline of its own.
     */
    public void testTricklingResponderIsCutOffAtTheDeadline()
        throws Exception
    {
        StubResponder responder = new StubResponder(StubResponder.MODE_TRICKLE);
        try
        {
            OcspStapleHttpFetcher fetcher = new OcspStapleHttpFetcher(responder.getURI(),
                RESPONSE_TIMEOUT_MS);

            long started = System.currentTimeMillis();
            try
            {
                fetcher.fetch(certID(), cert, null);
                fail("a trickling responder should not have been read to completion");
            }
            catch (IOException e)
            {
                assertTrue("unexpected failure: " + e.getMessage(),
                    e.getMessage().startsWith("timed out reading an OCSP response from"));
            }

            assertElapsedWithinBudget(System.currentTimeMillis() - started);
        }
        finally
        {
            responder.close();
        }
    }

    /**
     * The same bound where the responder goes silent mid-body rather than trickling: here it is the
     * read timeout that fires, and the point is that the wait is over in the same budget.
     */
    public void testSilentResponderIsCutOffAtTheDeadline()
        throws Exception
    {
        StubResponder responder = new StubResponder(StubResponder.MODE_STALL);
        try
        {
            OcspStapleHttpFetcher fetcher = new OcspStapleHttpFetcher(responder.getURI(),
                RESPONSE_TIMEOUT_MS);

            long started = System.currentTimeMillis();
            try
            {
                fetcher.fetch(certID(), cert, null);
                fail("a responder that stops mid-response should not have been waited out");
            }
            catch (IOException e)
            {
                // either our deadline or the read timeout beneath it, whichever came first
            }

            assertElapsedWithinBudget(System.currentTimeMillis() - started);
        }
        finally
        {
            responder.close();
        }
    }

    /**
     * A read already under way when the deadline passes still has to return before the deadline can
     * be acted on, so the bound is twice the budget rather than exactly it - as
     * {@link OcspStapleHttpFetcher}'s own javadoc says. Allow a further second for a loaded machine.
     */
    private void assertElapsedWithinBudget(long elapsedMs)
    {
        long limit = (2L * RESPONSE_TIMEOUT_MS) + 1000L;

        assertTrue("fetch took " + elapsedMs + "ms, which is beyond the " + limit + "ms bound",
            elapsedMs <= limit);
    }

    private static CertID certID()
    {
        // the contents are immaterial here: no test in this class gets as far as a parsed response
        byte[] hash = new byte[20];

        return new CertID(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1), new DEROctetString(hash),
            new DEROctetString(hash), new ASN1Integer(BigInteger.ONE));
    }

    private static KeyPair generateKeyPair()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(256);
        return kpg.generateKeyPair();
    }

    private static X509Certificate buildCert(X500Name issuer, PrivateKey issuerKey, X500Name subject,
        PublicKey subjectKey)
        throws Exception
    {
        long now = System.currentTimeMillis();

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuer,
            BigInteger.valueOf(++serialNumber), new Date(now - 5000), new Date(now + 30 * 60 * 1000),
            subject, SubjectPublicKeyInfo.getInstance(subjectKey.getEncoded()));

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
            .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(issuerKey);

        return new JcaX509CertificateConverter()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(builder.build(signer));
    }

    /**
     * An HTTP responder that answers with a Content-Length it never satisfies, either by handing over
     * a byte at a time indefinitely or by falling silent after the first one. Both shapes read as a
     * live connection to the layer beneath, which is the point.
     */
    private static class StubResponder
    {
        static final int MODE_TRICKLE = 0;
        static final int MODE_STALL = 1;

        private final ServerSocket serverSocket;
        private final int mode;
        private final Thread thread;

        private volatile boolean stopping = false;

        StubResponder(int mode)
            throws IOException
        {
            this.serverSocket = new ServerSocket(0);
            this.mode = mode;

            this.thread = new Thread(new Runnable()
            {
                public void run()
                {
                    acceptLoop();
                }
            }, "OcspStapleHttpFetcherTest-responder");

            thread.setDaemon(true);
            thread.start();
        }

        URI getURI()
        {
            return URI.create("http://localhost:" + serverSocket.getLocalPort() + "/ocsp");
        }

        void close()
        {
            stopping = true;

            try
            {
                serverSocket.close();
            }
            catch (IOException e)
            {
                // ignore
            }

            thread.interrupt();
        }

        private void acceptLoop()
        {
            while (!stopping)
            {
                Socket socket = null;
                try
                {
                    socket = serverSocket.accept();

                    serve(socket);
                }
                catch (IOException e)
                {
                    // the socket being closed under us is how this loop ends
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
        }

        private void serve(Socket socket)
            throws IOException
        {
            drainRequest(socket.getInputStream());

            OutputStream output = socket.getOutputStream();

            /*
             * A Content-Length this responder never satisfies, so the reader has every reason to keep
             * waiting for the rest of it. Kept well inside the response size limit, which is a
             * separate bound and not the one under test here.
             */
            output.write(Strings.toByteArray("HTTP/1.1 200 OK\r\n"
                + "Content-Type: application/ocsp-response\r\n"
                + "Content-Length: 4096\r\n"
                + "\r\n"));
            output.flush();

            output.write(0);
            output.flush();

            while (!stopping)
            {
                if (MODE_TRICKLE == mode)
                {
                    output.write(0);
                    output.flush();
                }

                try
                {
                    /*
                     * Trickling: comfortably inside the read timeout, so no single read of the
                     * client's ever times out and only its own deadline ends this. Stalling: nothing
                     * more is sent, but the connection is held open - closing it here would hand the
                     * client an EOF to finish on rather than a wait to be cut short.
                     */
                    Thread.sleep(RESPONSE_TIMEOUT_MS / 10);
                }
                catch (InterruptedException e)
                {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }

        /**
         * Read the request headers and body far enough that the client's write completes; what it
         * asked for makes no difference to what this responder does.
         */
        private void drainRequest(InputStream input)
            throws IOException
        {
            int contentLength = -1;
            String line;

            while (null != (line = readLine(input)) && line.length() > 0)
            {
                String lower = Strings.toLowerCase(line);
                if (lower.startsWith("content-length:"))
                {
                    contentLength = Integer.parseInt(line.substring(15).trim());
                }
            }

            for (int i = 0; i < contentLength; ++i)
            {
                if (input.read() < 0)
                {
                    break;
                }
            }
        }

        private static String readLine(InputStream input)
            throws IOException
        {
            StringBuffer line = new StringBuffer();

            for (;;)
            {
                int ch = input.read();
                if (ch < 0)
                {
                    return line.length() > 0 ? line.toString() : null;
                }
                if ('\n' == ch)
                {
                    int length = line.length();
                    if (length > 0 && '\r' == line.charAt(length - 1))
                    {
                        line.setLength(length - 1);
                    }
                    return line.toString();
                }

                line.append((char)ch);
            }
        }
    }
}
