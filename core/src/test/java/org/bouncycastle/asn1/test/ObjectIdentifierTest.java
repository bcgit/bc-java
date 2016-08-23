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
        for (int i = 0; i < 100; i++)
        {
            for (int j = 0; j < 100; j++)
            {
                final ASN1ObjectIdentifier oid1 = new ASN1ObjectIdentifier("1.1." + i + "." + j);
                final byte[] encoded1 = oid1.getEncoded();
                final ASN1ObjectIdentifier oid2 = ASN1ObjectIdentifier.getInstance(encoded1);
                if (oid1 == oid2)
                {
                    fail("Shouldn't be the same: " + oid1 + " " + oid2);
                }
                if (!oid1.equals(oid2))
                {
                    fail("Should be equal: " + oid1 + " " + oid2);
                }
                final ASN1ObjectIdentifier oid3 = oid2.intern();
                if (oid2 != oid3)
                {
                    fail("Should be the same: " + oid2 + " " + oid3);
                }
                if (!oid2.equals(oid3))
                {
                    fail("Should be equal: " + oid2 + " " + oid3);
                }
                final byte[] encoded2 = oid3.getEncoded();
                final ASN1ObjectIdentifier oid4 = ASN1ObjectIdentifier.getInstance(encoded2);
                if (oid3 != oid4)
                {
                    fail("Should be taken from cache: " + oid3 + " " + oid4);
                }
                if (!oid3.equals(oid4))
                {
                    fail("Should be equal: " + oid3 + " " + oid4);
                }
            }
        }

        // make sure we're not leaking memory
        for (int i = 0; i < 100; i++)
        {
            for (int j = 0; j < 100; j++)
            {
                final ASN1ObjectIdentifier oid1 = new ASN1ObjectIdentifier("1.1.2." + i + "." + j);
                final byte[] encoded1 = oid1.getEncoded();
                final ASN1ObjectIdentifier oid2 = ASN1ObjectIdentifier.getInstance(encoded1);
                final ASN1ObjectIdentifier oid3 = ASN1ObjectIdentifier.getInstance(encoded1);
                if (oid1 == oid2)
                {
                    fail("Shouldn't be the same: " + oid1 + " " + oid2);
                }
                if (oid2 == oid3)
                {
                    fail("Shouldn't be the same: " + oid2 + " " + oid3);
                }
            }
        }
    }

    public static void main(
        String[] args)
    {
        ObjectIdentifierTest test = new ObjectIdentifierTest();
        TestResult result = test.perform();

        System.out.println(result);
    }
}
