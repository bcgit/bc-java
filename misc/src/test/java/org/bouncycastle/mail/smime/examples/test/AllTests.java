package org.bouncycastle.mail.smime.examples.test;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.util.Enumeration;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.mail.smime.examples.CreateCompressedMail;
import org.bouncycastle.mail.smime.examples.CreateEncryptedMail;
import org.bouncycastle.mail.smime.examples.CreateLargeCompressedMail;
import org.bouncycastle.mail.smime.examples.CreateLargeEncryptedMail;
import org.bouncycastle.mail.smime.examples.CreateLargeSignedMail;
import org.bouncycastle.mail.smime.examples.CreateSignedMail;
import org.bouncycastle.mail.smime.examples.CreateSignedMultipartMail;
import org.bouncycastle.mail.smime.examples.ReadCompressedMail;
import org.bouncycastle.mail.smime.examples.ReadEncryptedMail;
import org.bouncycastle.mail.smime.examples.ReadLargeCompressedMail;
import org.bouncycastle.mail.smime.examples.ReadLargeEncryptedMail;
import org.bouncycastle.mail.smime.examples.ReadLargeSignedMail;
import org.bouncycastle.mail.smime.examples.ReadSignedMail;
import org.bouncycastle.mail.smime.examples.SendSignedAndEncryptedMail;
import org.bouncycastle.mail.smime.examples.ValidateSignedMail;
import org.bouncycastle.test.PrintTestResult;

/**
 * Smoke test that drives the S/MIME example programs (in
 * {@link org.bouncycastle.mail.smime.examples}) end to end via their {@code main} methods.
 * The examples themselves live in the non-Gradle {@code misc} tree, so this test does too.
 */
public class AllTests
    extends TestCase
{
    private PrintStream _oldOut;
    private PrintStream _oldErr;

    private ByteArrayOutputStream _currentOut;
    private ByteArrayOutputStream _currentErr;

    public void setUp()
    {
        _oldOut = System.out;
        _oldErr = System.err;
        _currentOut = new ByteArrayOutputStream();
        _currentErr = new ByteArrayOutputStream();

        System.setOut(new PrintStream(_currentOut));
        System.setErr(new PrintStream(_currentErr));
    }

    public void tearDown()
    {
        System.setOut(_oldOut);
        System.setErr(_oldErr);
    }

    public void testExamples()
        throws Exception
    {
        PKCS12FileCreator.main(null);
        CreateCompressedMail.main(null);
        CreateEncryptedMail.main(new String[]{"id.p12", "hello world"});
        CreateLargeCompressedMail.main(new String[]{"id.p12"});
        CreateLargeEncryptedMail.main(new String[]{"id.p12", "hello world", "encrypted.message"});
        CreateLargeSignedMail.main(new String[]{"id.p12"});
        CreateSignedMail.main(null);
        CreateSignedMultipartMail.main(null);
        ReadCompressedMail.main(null);
        ReadEncryptedMail.main(new String[]{"id.p12", "hello world"});
        ReadLargeCompressedMail.main(new String[]{"id.p12", "hello world"});
        ReadLargeEncryptedMail.main(new String[]{"id.p12", "hello world", "encrypted.message"});
        ReadLargeSignedMail.main(null);
        ReadSignedMail.main(null);

        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream("id.p12"), "hello world".toCharArray());

        Enumeration e = ks.aliases();
        String keyAlias = null;

        while (e.hasMoreElements())
        {
            String alias = (String)e.nextElement();

            if (ks.isKeyEntry(alias))
            {
                keyAlias = alias;
            }
        }

        // SendSignedAndEncryptedMail ends with Transport.send(), so the test must not point it
        // at a real mail host: JavaMail has no connect timeout by default, and where outbound
        // port 25 is silently dropped rather than refused the connect blocked the whole
        // :misc:test run indefinitely (github #2407). Deliver to a loopback SMTP stub instead,
        // with timeouts as a backstop; the example reads the mail.smtp.* settings from the
        // system properties.
        SmtpStub smtp = new SmtpStub();
        smtp.start();
        try
        {
            System.setProperty("mail.smtp.port", Integer.toString(smtp.getPort()));
            System.setProperty("mail.smtp.connectiontimeout", "10000");
            System.setProperty("mail.smtp.timeout", "10000");
            System.setProperty("mail.smtp.writetimeout", "10000");

            SendSignedAndEncryptedMail.main(new String[]{"id.p12", "hello world", keyAlias, "127.0.0.1", "recipient@example.com"});
        }
        finally
        {
            smtp.close();
        }
        assertTrue("SMTP stub did not receive the message: " + _currentErr, smtp.receivedMessage());

        ValidateSignedMail.main(null);
    }

    /**
     * Minimal single-connection SMTP responder on a loopback port: greets, answers every command
     * with 250, accepts one DATA body, and records that a message was delivered.
     */
    private static class SmtpStub
        extends Thread
    {
        private final ServerSocket serverSocket;
        private volatile boolean received;

        SmtpStub()
            throws IOException
        {
            serverSocket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
            serverSocket.setSoTimeout(30000);
            setDaemon(true);
        }

        int getPort()
        {
            return serverSocket.getLocalPort();
        }

        boolean receivedMessage()
        {
            return received;
        }

        public void run()
        {
            try
            {
                Socket socket = serverSocket.accept();
                try
                {
                    socket.setSoTimeout(30000);
                    BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), "ISO-8859-1"));
                    PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

                    out.print("220 localhost ESMTP stub\r\n");
                    out.flush();

                    boolean inData = false;
                    String line;
                    while ((line = in.readLine()) != null)
                    {
                        if (inData)
                        {
                            if (line.equals("."))
                            {
                                inData = false;
                                received = true;
                                out.print("250 OK\r\n");
                                out.flush();
                            }
                            continue;
                        }

                        String cmd = line.toUpperCase();
                        if (cmd.startsWith("EHLO") || cmd.startsWith("HELO"))
                        {
                            out.print("250 localhost\r\n");
                        }
                        else if (cmd.startsWith("DATA"))
                        {
                            inData = true;
                            out.print("354 End data with <CR><LF>.<CR><LF>\r\n");
                        }
                        else if (cmd.startsWith("QUIT"))
                        {
                            out.print("221 Bye\r\n");
                            out.flush();
                            break;
                        }
                        else
                        {
                            out.print("250 OK\r\n");
                        }
                        out.flush();
                    }
                }
                finally
                {
                    socket.close();
                }
            }
            catch (IOException e)
            {
                // accept timed out or the client went away: receivedMessage() reports the result
            }
        }

        void close()
            throws IOException
        {
            serverSocket.close();
            try
            {
                join(30000);
            }
            catch (InterruptedException e)
            {
                Thread.currentThread().interrupt();
            }
        }
    }

    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("S/MIME Example Tests");

        suite.addTestSuite(AllTests.class);

        return suite;
    }
}
