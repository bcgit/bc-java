package org.bouncycastle.util.io.pem.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.pem.PemHeader;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

public class AllTests
    extends TestCase
{
    private static final String blob1 =
        "-----BEGIN BLOB-----\r\n"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\r\n"
        + "-----END BLOB-----\r\n";

    private static final String blob2 =
        "-----BEGIN BLOB-----   \r\n"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\r\n"
        + "-----END BLOB-----    \r\n";

    private static final String blob3 =
        "    -----BEGIN BLOB-----\r\n"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\r\n"
        + "-----END BLOB-----\r\n";

    private static final String blob4 =
        "-----BEGIN BLOB-----\r\n"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\r\n"
        + "    -----END BLOB-----\r\n";

    public void testPemLength()
        throws IOException
    {
        for (int i = 1; i != 60; i++)
        {
            lengthTest("CERTIFICATE", Collections.EMPTY_LIST, new byte[i]);
        }

        lengthTest("CERTIFICATE", Collections.EMPTY_LIST, new byte[100]);
        lengthTest("CERTIFICATE", Collections.EMPTY_LIST, new byte[101]);
        lengthTest("CERTIFICATE", Collections.EMPTY_LIST, new byte[102]);
        lengthTest("CERTIFICATE", Collections.EMPTY_LIST, new byte[103]);

        lengthTest("CERTIFICATE", Collections.EMPTY_LIST, new byte[1000]);
        lengthTest("CERTIFICATE", Collections.EMPTY_LIST, new byte[1001]);
        lengthTest("CERTIFICATE", Collections.EMPTY_LIST, new byte[1002]);
        lengthTest("CERTIFICATE", Collections.EMPTY_LIST, new byte[1003]);

        List headers = new ArrayList();

        headers.add(new PemHeader("Proc-Type", "4,ENCRYPTED"));
        headers.add(new PemHeader("DEK-Info", "DES3,0001020304050607"));

        lengthTest("RSA PRIVATE KEY", headers, new byte[103]);
    }

    public void testMalformed()
        throws IOException
    {
        PemReader rd = new PemReader(new StringReader("-----BEGIN \n"));

        assertNull(rd.readPemObject());
    }

    public void testRegularBlob()
        throws IOException
    {
        PemReader rd = new PemReader(new StringReader(blob1));

        PemObject obj = rd.readPemObject();

        assertEquals("BLOB", obj.getType());
        assertTrue(Arrays.areEqual(new byte[64], obj.getContent()));
    }

    public void testRegularBlobTrailing()
        throws IOException
    {
        PemReader rd = new PemReader(new StringReader(blob2));

        PemObject obj = rd.readPemObject();

        assertEquals("BLOB", obj.getType());
        assertTrue(Arrays.areEqual(new byte[64], obj.getContent()));
    }

    public void testRegularBlobBeginFault()
        throws IOException
    {
        PemReader rd = new PemReader(new StringReader(blob3));

        PemObject obj = rd.readPemObject();

        assertNull(rd.readPemObject());
    }

    public void testRegularBlobEndFault()
        throws IOException
    {
        PemReader rd = new PemReader(new StringReader(blob4));

        try
        {
            PemObject obj = rd.readPemObject();
        }
        catch (IOException e)
        {
            assertEquals("-----END BLOB----- not found", e.getMessage());
        }
    }

    public void testRegularBlobEndLaxParsing()
        throws IOException
    {
        String original = System.setProperty(PemReader.LAX_PEM_PARSING_SYSTEM_PROPERTY_NAME, "true");
        PemReader rd = new PemReader(new StringReader(blob4));

        PemObject obj;
        try
        {
            obj = rd.readPemObject();
        }
        finally
        {
            if (original != null)
            {
                System.setProperty(PemReader.LAX_PEM_PARSING_SYSTEM_PROPERTY_NAME, original);
            }
            else
            {
                System.setProperty(PemReader.LAX_PEM_PARSING_SYSTEM_PROPERTY_NAME, "");
            }
        }

        assertEquals("BLOB", obj.getType());
        assertTrue(Arrays.areEqual(new byte[64], obj.getContent()));

    }

    private void lengthTest(String type, List headers, byte[] data)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PemWriter pWrt = new PemWriter(new OutputStreamWriter(bOut));

        PemObject pemObj = new PemObject(type, headers, data);
        pWrt.writeObject(pemObj);

        pWrt.close();

        assertEquals(bOut.toByteArray().length, pWrt.getOutputSize(pemObj));
    }

    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("PEM Tests");
        suite.addTestSuite(AllTests.class);
        return suite;
    }
}
