package org.bouncycastle.asn1.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1RelativeOID;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class RelativeOIDTest
    extends SimpleTest
{
    private static final String ALLOW_WRONG_OID_ENC = "org.bouncycastle.asn1.allow_wrong_oid_enc";

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
        isTrue(ASN1RelativeOID.tryFromID(oid) != null);

        ASN1RelativeOID o = new ASN1RelativeOID(oid);
        o = (ASN1RelativeOID)ASN1Primitive.fromByteArray(o.getEncoded());
        if (!o.getId().equals(oid))
        {
            fail("failed relative oid check for " + oid);
        }
    }

    private void checkInvalid(String oid)
    {
        isTrue(ASN1RelativeOID.tryFromID(oid) == null);

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
        checkValid("9");
        checkValid("99");
        checkValid("999");
        checkValid("9999");
        checkValid("99999");
        checkValid("999999");
        checkValid("999999999999999999");
        checkValid("9999999999999999999");
        checkValid("99999999999999999999");

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

        wrongEncodingTest();
    }

    /**
     * Under the "org.bouncycastle.asn1.allow_wrong_oid_enc" override an invalid encoding is read as the
     * identifier it corrects to, but re-encodes exactly as received. Without the override it is refused.
     */
    private void wrongEncodingTest()
        throws IOException
    {
        // 3 with one and two redundant octets, 42.1 unterminated, a lone continuation octet, only
        // continuation octets, and no contents at all
        byte[] oneRedundant = Hex.decode("0D028003");
        byte[] twoRedundant = Hex.decode("0D03808003");
        byte[] unterminated = Hex.decode("0D022A81");
        byte[] loneOctet = Hex.decode("0D0180");
        byte[] twoOctets = Hex.decode("0D028080");
        byte[] empty = Hex.decode("0D00");

        Properties.setThreadOverride(ALLOW_WRONG_OID_ENC, true);
        try
        {
            checkWrongEncoding(oneRedundant, "3");
            checkWrongEncoding(twoRedundant, "3");
            checkWrongEncoding(unterminated, "42.1");
            checkWrongEncoding(loneOctet, "0");
            checkWrongEncoding(twoOctets, "0");

            ASN1RelativeOID emptyOID = ASN1RelativeOID.getInstance(empty);
            isEquals("empty: identifier", "", emptyOID.getId());
            isTrue("empty: re-encoding", Arrays.areEqual(empty, emptyOID.getEncoded()));
            isTrue("empty: single instance", ASN1RelativeOID.getInstance(empty) == emptyOID
                && ASN1RelativeOID.fromContents(new byte[0]) == emptyOID);
            isTrue("empty: not a valid identifier", !emptyOID.equals(new ASN1RelativeOID("0")));
            try
            {
                emptyOID.branch("1");
                fail("empty: branch accepted");
            }
            catch (IllegalStateException e)
            {
                isEquals("empty identifier has no branches", e.getMessage());
            }
        }
        finally
        {
            Properties.removeThreadOverride(ALLOW_WRONG_OID_ENC);
        }

        byte[][] invalid = { oneRedundant, twoRedundant, unterminated, loneOctet, twoOctets, empty };
        for (int i = 0; i != invalid.length; i++)
        {
            try
            {
                ASN1RelativeOID.fromContents(Arrays.copyOfRange(invalid[i], 2, invalid[i].length));
                fail("no exception without the override: " + Hex.toHexString(invalid[i]));
            }
            catch (IllegalArgumentException e)
            {
                isEquals("invalid relative OID contents", e.getMessage());
            }
        }
    }

    private void checkWrongEncoding(byte[] encoding, String expectedId)
        throws IOException
    {
        String label = Hex.toHexString(encoding) + ": ";
        ASN1RelativeOID valid = new ASN1RelativeOID(expectedId);
        isTrue(label + "a valid encoding was given", !Arrays.areEqual(encoding, valid.getEncoded()));

        ASN1RelativeOID oid = ASN1RelativeOID.getInstance(encoding);
        isEquals(label + "identifier", expectedId, oid.getId());
        isTrue(label + "re-encoding", Arrays.areEqual(encoding, oid.getEncoded()));
        isTrue(label + "DER re-encoding", Arrays.areEqual(encoding, oid.getEncoded(ASN1Encoding.DER)));
        isTrue(label + "equals", oid.equals(valid) && valid.equals(oid));
        isTrue(label + "hashCode", oid.hashCode() == valid.hashCode());
        isTrue(label + "branch", Arrays.areEqual(valid.branch("1").getEncoded(), oid.branch("1").getEncoded()));

        byte[] contents = Arrays.copyOfRange(encoding, 2, encoding.length);
        ASN1RelativeOID fromContents = ASN1RelativeOID.fromContents(contents);
        isTrue(label + "fromContents", fromContents.equals(valid) && Arrays.areEqual(encoding, fromContents.getEncoded()));

        ASN1RelativeOID again = ASN1RelativeOID.getInstance(encoding);
        isTrue(label + "a fresh instance each time", again != oid && Arrays.areEqual(encoding, again.getEncoded()));
    }

    public static void main(String[] args)
    {
        runTest(new RelativeOIDTest());
    }
}
