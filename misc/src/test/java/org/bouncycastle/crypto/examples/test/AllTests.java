package org.bouncycastle.crypto.examples.test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.crypto.examples.SM9EngineExample;
import org.bouncycastle.crypto.examples.SM9KEMExample;
import org.bouncycastle.crypto.examples.SM9KeyExchangeExample;
import org.bouncycastle.crypto.examples.SM9SignerExample;
import org.bouncycastle.test.PrintTestResult;
import org.bouncycastle.util.Strings;

/**
 * Smoke tests for the lightweight SM9 examples, so that an API change which still compiles cannot
 * break one unnoticed. Each test runs the example's main(), so a failing example fails the test with
 * its own exception, and checks the line it prints on success.
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

    public void testSM9EngineExample()
        throws Exception
    {
        SM9EngineExample.main(new String[0]);
        assertPrinted("message encrypted to \"Bob\" and recovered in both GM/T 0044.4 modes.");
    }

    public void testSM9KEMExample()
        throws Exception
    {
        SM9KEMExample.main(new String[0]);
        assertPrinted("shared 128-bit key encapsulated to \"Bob\" and recovered");
    }

    public void testSM9KeyExchangeExample()
        throws Exception
    {
        SM9KeyExchangeExample.main(new String[0]);
        assertPrinted("shared 128-bit key agreed and confirmed between \"Alice\" and \"Bob\".");
    }

    public void testSM9SignerExample()
        throws Exception
    {
        SM9SignerExample.main(new String[0]);
        assertPrinted("verified for \"Alice\" against the master public key + identity.");
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
