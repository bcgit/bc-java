package org.bouncycastle.asn1.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1RelativeOID;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class RelativeOIDTest
    extends SimpleTest
{
    private static final byte[] req1 = Hex.decode("0D03813403");
    private static final byte[] req2 = Hex.decode("0D082A36FFFFFFDD6311");

    public String getName()
    {
        return "RelativeOID";
    }

    private void recodeCheck(String oid, byte[] enc) throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(enc);
        ASN1InputStream aIn = new ASN1InputStream(bIn);

        ASN1RelativeOID o = new ASN1RelativeOID(oid);
        ASN1RelativeOID encO = (ASN1RelativeOID)aIn.readObject();

        if (!o.equals(encO))
        {
            fail("relative OID didn't match", o, encO);
        }

        byte[] bytes = o.getEncoded(ASN1Encoding.DER);

        if (bytes.length != enc.length)
        {
            fail("failed length test");
        }

        for (int i = 0; i != enc.length; i++)
        {
            if (bytes[i] != enc[i])
            {
                fail("failed comparison test", new String(Hex.encode(enc)), new String(Hex.encode(bytes)));
            }
        }
    }

    private void checkValid(String oid) throws IOException
    {
        ASN1RelativeOID o = new ASN1RelativeOID(oid);
        o = (ASN1RelativeOID)ASN1Primitive.fromByteArray(o.getEncoded());
        if (!o.getId().equals(oid))
        {
            fail("failed relative oid check for " + oid);
        }
    }

    private void checkInvalid(String oid)
    {
        try
        {
            new ASN1RelativeOID(oid);
            fail("failed to catch bad relative oid: " + oid);
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void branchCheck(String stem, String branch)
    {
        String expected = stem + "." + branch;
        String actual = new ASN1RelativeOID(stem).branch(branch).getId();

        if (!expected.equals(actual))
        {
            fail("failed 'branch' check for " + stem + "/" + branch);
        }
    }

    public void performTest()
        throws IOException
    {
        recodeCheck("180.3", req1);
        recodeCheck("42.54.34359733987.17", req2);

        checkValid("0");
        checkValid("37");
        checkValid("0.1");
        checkValid("1.0");
        checkValid("1.0.2");
        checkValid("1.0.20");
        checkValid("1.0.200");
        checkValid("1.1.127.32512.8323072.2130706432.545460846592.139637976727552.35747322042253312.9151314442816847872");
        checkValid("1.2.123.12345678901.1.1.1");
        checkValid("2.25.196556539987194312349856245628873852187.1");
        checkValid("3.1");
        checkValid("37.196556539987194312349856245628873852187.100");
        checkValid("192.168.1.1");

        checkInvalid("00");
        checkInvalid("0.01");
        checkInvalid("00.1");
        checkInvalid("1.00.2");
        checkInvalid("1.0.02");
        checkInvalid("1.2.00");
        checkInvalid(".1");
        checkInvalid("..1");
        checkInvalid("3..1");
        checkInvalid(".123452");
        checkInvalid("1.");
        checkInvalid("1.345.23.34..234");
        checkInvalid("1.345.23.34.234.");
        checkInvalid(".12.345.77.234");
        checkInvalid(".12.345.77.234.");
        checkInvalid("1.2.3.4.A.5");
        checkInvalid("1,2");

        branchCheck("1.1", "2.2");
    }

    public static void main(String[] args)
    {
        runTest(new RelativeOIDTest());
    }
}
