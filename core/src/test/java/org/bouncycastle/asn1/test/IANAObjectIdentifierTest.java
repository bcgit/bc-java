package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.internal.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestResult;

public class IANAObjectIdentifierTest
    extends SimpleTest
{
    public String getName()
    {
        return "IANAObjectIdentifier";
    }

    public void performTest()
        throws Exception
    {
        isEquals("wrong internet", new ASN1ObjectIdentifier("1.3.6.1"), IANAObjectIdentifiers.internet);
        isEquals("wrong id-alg", new ASN1ObjectIdentifier("1.3.6.1.5.5.7.6"), IANAObjectIdentifiers.id_alg);
        isEquals(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.6.37"), IANAObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256);
        isEquals(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.6.54"), IANAObjectIdentifiers.id_MLDSA87_ECDSA_P521_SHA512);
    }

    public static void main(
        String[] args)
    {
        IANAObjectIdentifierTest test = new IANAObjectIdentifierTest();
        TestResult result = test.perform();

        System.out.println(result);
    }
}
