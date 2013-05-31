package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestResult;

public class ObjectIdentifierTest
    extends SimpleTest
{
    public String getName()
    {
        return "ObjectIdentifier";
    }

    public void performTest()
        throws Exception
    {
        // exercise the object cache
        for (int i = 0; i < 1024; i++)
        {
            for (int j = 0; j != 17000; j++)
            {
                byte[] encoded = new ASN1ObjectIdentifier("1.1." + i + "." + j).getEncoded();

                ASN1ObjectIdentifier.getInstance(encoded);
            }
        }
    }

    public static void main(
        String[] args)
    {
        ObjectIdentifierTest    test = new ObjectIdentifierTest();
        TestResult result = test.perform();

        System.out.println(result);
    }
}
