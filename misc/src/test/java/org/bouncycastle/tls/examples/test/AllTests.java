package org.bouncycastle.tls.examples.test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;
import org.bouncycastle.tls.examples.OCSPStaplingServerExample;
import org.bouncycastle.util.Strings;

/**
 * Smoke tests for the org.bouncycastle.tls examples, so they don't rot against the library API.
 */
public class AllTests
    extends TestCase
{
    public void testOCSPStaplingServerExample()
        throws Exception
    {
        String output = runCapturingStdout();

        // The RFC 6066 "status_request" handshake.
        assertTrue(output.indexOf("TLS server stapling ocsp status") >= 0);
        assertTrue(output.indexOf("TLS client received a stapled ocsp status") >= 0);

        // The RFC 6961 "status_request_v2" handshake.
        assertTrue(output.indexOf("TLS server stapling ocsp_multi status") >= 0);
        assertTrue(output.indexOf("TLS client received a stapled ocsp_multi status") >= 0);

        // Both clients verified the stapled response against the certificate it arrived with.
        assertTrue(output.indexOf("INVALID") < 0);
        assertTrue(output.indexOf("DOES NOT MATCH") < 0);

        int goodCount = 0;
        for (int i = output.indexOf("good ("); i >= 0; i = output.indexOf("good (", i + 1))
        {
            ++goodCount;
        }
        assertEquals(2, goodCount);
    }

    private String runCapturingStdout()
        throws Exception
    {
        ByteArrayOutputStream captured = new ByteArrayOutputStream();

        PrintStream originalOut = System.out;
        try
        {
            System.setOut(new PrintStream(captured));

            OCSPStaplingServerExample.main(new String[0]);
        }
        finally
        {
            System.setOut(originalOut);
        }

        return Strings.fromByteArray(captured.toByteArray());
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
