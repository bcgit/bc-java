package org.bouncycastle.mail.smime.examples.test;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.PrintStream;
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

        SendSignedAndEncryptedMail.main(new String[]{"id.p12", "hello world", keyAlias, "smtp.gmail.com", "recipient@example.com"});
        ValidateSignedMail.main(null);
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
