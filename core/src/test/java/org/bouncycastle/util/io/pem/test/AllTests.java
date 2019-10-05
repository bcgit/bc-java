package org.bouncycastle.util.io.pem.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.util.io.pem.PemHeader;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

public class AllTests
    extends TestCase
{
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
}