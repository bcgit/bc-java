package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509ExtensionsGenerator;
import org.bouncycastle.util.test.SimpleTest;

public class X509ExtensionsTest
    extends SimpleTest
{
    private static final ASN1ObjectIdentifier OID_2 = new ASN1ObjectIdentifier("1.2.2");
    private static final ASN1ObjectIdentifier OID_3 = new ASN1ObjectIdentifier("1.2.3");
    private static final ASN1ObjectIdentifier OID_1 = new ASN1ObjectIdentifier("1.2.1");

    public String getName()
    {
        return "X509Extensions";
    }

    public void performTest() throws Exception
    {
        X509ExtensionsGenerator gen = new X509ExtensionsGenerator();

        gen.addExtension(OID_1, true, new byte[20]);
        gen.addExtension(OID_2, true, new byte[20]);

        X509Extensions ext1 = gen.generate();
        X509Extensions ext2 = gen.generate();

        if (!ext1.equals(ext2))
        {
            fail("equals test failed");
        }

        gen.reset();

        gen.addExtension(OID_2, true, new byte[20]);
        gen.addExtension(OID_1, true, new byte[20]);

        ext2 = gen.generate();

        if (ext1.equals(ext2))
        {
            fail("inequality test failed");
        }

        if (!ext1.equivalent(ext2))
        {
            fail("equivalence true failed");
        }

        gen.reset();

        gen.addExtension(OID_1, true, new byte[22]);
        gen.addExtension(OID_2, true, new byte[20]);

        ext2 = gen.generate();

        if (ext1.equals(ext2))
        {
            fail("inequality 1 failed");
        }

        if (ext1.equivalent(ext2))
        {
            fail("non-equivalence 1 failed");
        }

        gen.reset();

        gen.addExtension(OID_3, true, new byte[20]);
        gen.addExtension(OID_2, true, new byte[20]);

        ext2 = gen.generate();

        if (ext1.equals(ext2))
        {
            fail("inequality 2 failed");
        }

        if (ext1.equivalent(ext2))
        {
            fail("non-equivalence 2 failed");
        }

        try
        {
            gen.addExtension(OID_2, true, new byte[20]);
            fail("repeated oid");
        }
        catch (IllegalArgumentException e)
        {
            if (!e.getMessage().equals("extension 1.2.2 already added"))
            {
                fail("wrong exception on repeated oid: " + e.getMessage());
            }
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new X509ExtensionsTest());
    }
}
