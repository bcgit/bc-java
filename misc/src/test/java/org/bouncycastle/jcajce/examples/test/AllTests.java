package org.bouncycastle.jcajce.examples.test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.jcajce.examples.SM9CipherExample;
import org.bouncycastle.jcajce.examples.SM9EncKeyEncodingExample;
import org.bouncycastle.jcajce.examples.SM9Example;
import org.bouncycastle.jcajce.examples.SM9KeyAgreementExample;
import org.bouncycastle.jcajce.examples.SM9SigExample;
import org.bouncycastle.jcajce.examples.SM9SigKeyEncodingExample;
import org.bouncycastle.test.PrintTestResult;
import org.bouncycastle.util.Strings;

/**
 * Smoke tests for the JCA SM9 examples, so that an API change which still compiles - a
 * transformation string an example uses, say - cannot break one unnoticed. Each test runs the
 * example's main(), so a failing example fails the test with its own exception, and checks the line
 * it prints on success.
 */
public class AllTests
    extends TestCase
{
    private PrintStream originalOut;
    private ByteArrayOutputStream captured;

    public void setUp()
    {
        originalOut = System.out;
        captured = new ByteArrayOutputStream();
        System.setOut(new PrintStream(captured));
    }

    public void tearDown()
    {
        System.setOut(originalOut);
    }

    public void testSM9CipherExample()
        throws Exception
    {
        SM9CipherExample.main(new String[0]);
        assertPrinted("both data-encapsulation modes round-trip for \"Bob\".");
    }

    public void testSM9EncKeyEncodingExample()
        throws Exception
    {
        SM9EncKeyEncodingExample.main(new String[0]);
        assertPrinted("decrypted with the rebuilt key: Chinese IBE standard");
    }

    public void testSM9Example()
        throws Exception
    {
        SM9Example.main(new String[0]);
        assertPrinted("shared 128-bit AES key established with \"Bob\".");
    }

    public void testSM9KeyAgreementExample()
        throws Exception
    {
        SM9KeyAgreementExample.main(new String[0]);
        assertPrinted("shared 128-bit key agreed between \"Alice\" and \"Bob\" through KeyAgreement.SM9.");
    }

    public void testSM9SigExample()
        throws Exception
    {
        SM9SigExample.main(new String[0]);
        assertPrinted("verified for \"Alice\" against the master public key + identity.");
    }

    public void testSM9SigKeyEncodingExample()
        throws Exception
    {
        SM9SigKeyEncodingExample.main(new String[0]);
        assertPrinted("signature from the rebuilt key verified.");
    }

    private void assertPrinted(String line)
    {
        assertTrue(Strings.fromByteArray(captured.toByteArray()).indexOf(line) >= 0);
    }

    public static void main(String[] args)
        throws Exception
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
        throws Exception
    {
        return new TestSuite(AllTests.class);
    }
}
