package org.bouncycastle.asn1.test;


import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.crmf.DhSigStatic;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class DhSigStaticTest
    extends SimpleTest
{


    public void performTest()
        throws Exception
    {
        // Test correct encode / decode

        // Test encode and decode from Long and from other instance of DhSigStatic
        DhSigStatic dhS = new DhSigStatic(new byte[20]);
        instanceTest(dhS);

        dhS = new DhSigStatic(new IssuerAndSerialNumber(new X500Name("CN=Test"), BigInteger.valueOf(20)), new byte[20]);
        instanceTest(dhS);

        dhS = DhSigStatic.getInstance(new DERSequence(new DEROctetString(Hex.decode("0102030405060708090a"))));

        isTrue(Arrays.areEqual(Hex.decode("0102030405060708090a"), dhS.getHashValue()));

        try
        {
            dhS = DhSigStatic.getInstance(new DERSequence(
                new ASN1Encodable[] {
                    new DEROctetString(Hex.decode("0102030405060708090a")),
                    new DEROctetString(Hex.decode("0102030405060708090a")),
                    new DEROctetString(Hex.decode("0102030405060708090a")) }));
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals(e.getMessage(), "sequence wrong length for DhSigStatic", e.getMessage());
        }
    }

    private void instanceTest(DhSigStatic bpd)
        throws IOException
    {
        byte[] b = bpd.getEncoded();
        DhSigStatic resBpd = DhSigStatic.getInstance(b);
        isTrue("hash check failed", areEqual(bpd.getHashValue(), resBpd.getHashValue()));
        isEquals("issuerAndSerial failed", bpd.getIssuerAndSerial(), resBpd.getIssuerAndSerial());
    }

    public String getName()
    {
        return "DhSigStaticTest";
    }

    public static void main(String[] args)
        throws Exception
    {
        runTest(new DhSigStaticTest());
    }
}

