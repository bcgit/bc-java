package org.bouncycastle.jsse.provider.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

/**
 * A minimal OCSP responder over HTTP, for exercising the server-side stapling path end to end.
 * <p/>
 * Binds an ephemeral port so a test can put the resulting URL into the certificates it then
 * generates, and counts the requests it serves so a test can assert on how often the server went out
 * to the network - which is the point of the stapling cache.
 * <p/>
 * Every response is signed with the one key the responder is built with, whichever certificate is
 * asked about. Nothing in the stapling path verifies a relayed response - the client does that - so
 * these tests assert the plumbing, not response validation.
 */
class TestOCSPResponder
{
    private final ServerSocket serverSocket;
    private final PublicKey signerPublicKey;
    private final PrivateKey signerPrivateKey;
    private final String signatureAlgorithm;
    private final X509CertificateHolder[] chain;
    private final Thread thread;

    private int requestCount = 0;
    private volatile boolean stopping = false;
    private volatile boolean omitNextUpdate = false;

    TestOCSPResponder(PublicKey signerPublicKey, PrivateKey signerPrivateKey, String signatureAlgorithm,
        X509CertificateHolder[] chain)
        throws IOException
    {
        this.serverSocket = new ServerSocket(0);
        this.signerPublicKey = signerPublicKey;
        this.signerPrivateKey = signerPrivateKey;
        this.signatureAlgorithm = signatureAlgorithm;
        this.chain = chain;

        this.thread = new Thread(new Runnable()
        {
            public void run()
            {
                acceptLoop();
            }
        }, "TestOCSPResponder");

        thread.setDaemon(true);
        thread.start();
    }

    String getURL()
    {
        return "http://localhost:" + serverSocket.getLocalPort() + "/ocsp";
    }

    synchronized int getRequestCount()
    {
        return requestCount;
    }

    /**
     * Answer without a nextUpdate. RFC 6960 sec. 4.2.2.1 makes such a response unreusable, so it
     * must be stapled to the handshake it arrived for and then forgotten.
     */
    void setOmitNextUpdate(boolean omitNextUpdate)
    {
        this.omitNextUpdate = omitNextUpdate;
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

        try
        {
            thread.join(10000);
        }
        catch (InterruptedException e)
        {
            Thread.currentThread().interrupt();
        }
    }

    private void acceptLoop()
    {
        while (!stopping)
        {
            Socket socket = null;
            try
            {
                socket = serverSocket.accept();

                handle(socket);
            }
            catch (Exception e)
            {
                if (!stopping)
                {
                    e.printStackTrace();
                }
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

    private void handle(Socket socket)
        throws Exception
    {
        InputStream input = socket.getInputStream();

        int contentLength = -1;
        String line;
        while (null != (line = readLine(input)) && line.length() > 0)
        {
            String lowerCase = Strings.toLowerCase(line);
            if (lowerCase.startsWith("content-length:"))
            {
                contentLength = Integer.parseInt(line.substring("content-length:".length()).trim());
            }
        }

        if (contentLength < 0)
        {
            throw new IOException("no Content-Length in OCSP request");
        }

        byte[] body = new byte[contentLength];
        Streams.readFully(input, body);

        synchronized (this)
        {
            ++requestCount;
        }

        byte[] response = respond(new OCSPReq(body)).getEncoded();

        OutputStream output = socket.getOutputStream();
        output.write(Strings.toByteArray("HTTP/1.1 200 OK\r\n"
            + "Content-Type: application/ocsp-response\r\n"
            + "Content-Length: " + response.length + "\r\n"
            + "Connection: close\r\n"
            + "\r\n"));
        output.write(response);
        output.flush();
    }

    private OCSPResp respond(OCSPReq request)
        throws Exception
    {
        BasicOCSPRespBuilder respBuilder = new JcaBasicOCSPRespBuilder(signerPublicKey,
            new JcaDigestCalculatorProviderBuilder().build().get(RespID.HASH_SHA1));

        Date thisUpdate = new Date(System.currentTimeMillis() - 60 * 1000L);
        Date nextUpdate = omitNextUpdate ? null : new Date(System.currentTimeMillis() + 3600 * 1000L);

        Req[] requests = request.getRequestList();
        for (int i = 0; i != requests.length; i++)
        {
            CertificateID certID = requests[i].getCertID();

            // NOTE: echoing the requested CertID is what lets the response be bound to the certificate
            respBuilder.addResponse(certID, CertificateStatus.GOOD, thisUpdate, nextUpdate);
        }

        BasicOCSPResp basicResp = respBuilder.build(
            new JcaContentSignerBuilder(signatureAlgorithm).build(signerPrivateKey), chain, new Date());

        return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basicResp);
    }

    private static String readLine(InputStream input)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        int ch;
        while (-1 != (ch = input.read()))
        {
            if ('\n' == ch)
            {
                break;
            }
            if ('\r' != ch)
            {
                buf.write(ch);
            }
        }

        return Strings.fromByteArray(buf.toByteArray());
    }
}
