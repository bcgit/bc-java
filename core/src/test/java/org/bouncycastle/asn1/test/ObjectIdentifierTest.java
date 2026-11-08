package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestResult;

public class ObjectIdentifierTest
    extends SimpleTest
{
    private static final String ALLOW_WRONG_OID_ENC = "org.bouncycastle.asn1.allow_wrong_oid_enc";

    public String getName()
    {
        return "ObjectIdentifier";
    }

    public void performTest()
        throws Exception
    {
        try
        {
            ASN1ObjectIdentifier.fromContents(new byte[0]);
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("invalid OID contents", e.getMessage());
        }

        byte[] faultyOID = Hex.decode("06092A864886FC6B048000");
        try
        {
            ASN1ObjectIdentifier.getInstance(faultyOID);
            fail("no exception");
        }
        catch (Exception e)
        {
            isEquals("failed to construct object identifier from byte[]", e.getMessage());
        }

        System.setProperty("org.bouncycastle.asn1.allow_wrong_oid_enc", "true");
        String oid = ASN1ObjectIdentifier.getInstance(faultyOID).getId();

        System.setProperty("org.bouncycastle.asn1.allow_wrong_oid_enc", "false");
        isEquals("1.2.840.114283.4.0", oid);

        wrongEncodingTest();

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

    /**
     * Under the "org.bouncycastle.asn1.allow_wrong_oid_enc" override an invalid encoding is read as the
     * identifier it corrects to, but re-encodes exactly as received, and the pool never holds it. Without
     * the override it is refused.
     */
    private void wrongEncodingTest()
        throws Exception
    {
        // github #1758: the final subidentifier 0 encoded as 80 00
        byte[] faultyOID = Hex.decode("06092A864886FC6B048000");
        // 1.2.3 with two redundant octets, with a redundant octet in the first subidentifier, and unterminated
        byte[] twoRedundant = Hex.decode("06042A808003");
        byte[] firstRedundant = Hex.decode("0603802A03");
        byte[] unterminated = Hex.decode("06022A81");
        // a lone continuation octet, and only continuation octets
        byte[] loneOctet = Hex.decode("060180");
        byte[] twoOctets = Hex.decode("06028080");
        // github #1639: no contents at all
        byte[] empty = Hex.decode("0600");

        Properties.setThreadOverride(ALLOW_WRONG_OID_ENC, true);
        try
        {
            checkWrongEncoding(faultyOID, "1.2.840.114283.4.0");
            checkWrongEncoding(twoRedundant, "1.2.3");
            checkWrongEncoding(firstRedundant, "1.2.3");
            checkWrongEncoding(unterminated, "1.2.1");
            checkWrongEncoding(loneOctet, "0.0");
            checkWrongEncoding(twoOctets, "0.0");

            ASN1ObjectIdentifier emptyOID = ASN1ObjectIdentifier.getInstance(empty);
            isEquals("empty: identifier", "", emptyOID.getId());
            isTrue("empty: re-encoding", Arrays.areEqual(empty, emptyOID.getEncoded()));
            isTrue("empty: single instance", ASN1ObjectIdentifier.getInstance(empty) == emptyOID
                && ASN1ObjectIdentifier.fromContents(new byte[0]) == emptyOID);
            isTrue("empty: intern", emptyOID.intern() == emptyOID);
            isTrue("empty: not a valid identifier", !emptyOID.equals(new ASN1ObjectIdentifier("0.0")));
            isTrue("empty: on nothing, nothing on it", !emptyOID.on(new ASN1ObjectIdentifier("0.0"))
                && !new ASN1ObjectIdentifier("0.0").on(emptyOID) && !emptyOID.on(emptyOID));
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

        byte[][] invalid = { faultyOID, twoRedundant, firstRedundant, unterminated, loneOctet, twoOctets, empty };
        for (int i = 0; i != invalid.length; i++)
        {
            try
            {
                ASN1ObjectIdentifier.fromContents(Arrays.copyOfRange(invalid[i], 2, invalid[i].length));
                fail("no exception without the override: " + Hex.toHexString(invalid[i]));
            }
            catch (IllegalArgumentException e)
            {
                isEquals("invalid OID contents", e.getMessage());
            }
        }
    }

    private void checkWrongEncoding(byte[] encoding, String expectedId)
        throws Exception
    {
        String label = Hex.toHexString(encoding) + ": ";
        ASN1ObjectIdentifier valid = new ASN1ObjectIdentifier(expectedId);
        isTrue(label + "a valid encoding was given", !Arrays.areEqual(encoding, valid.getEncoded()));

        ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(encoding);
        isEquals(label + "identifier", expectedId, oid.getId());
        isTrue(label + "re-encoding", Arrays.areEqual(encoding, oid.getEncoded()));
        isTrue(label + "DER re-encoding", Arrays.areEqual(encoding, oid.getEncoded(ASN1Encoding.DER)));
        isTrue(label + "equals", oid.equals(valid) && valid.equals(oid));
        isTrue(label + "hashCode", oid.hashCode() == valid.hashCode());
        isTrue(label + "branch", Arrays.areEqual(valid.branch("1").getEncoded(), oid.branch("1").getEncoded()));
        isTrue(label + "on", oid.branch("1").on(valid) && valid.branch("1").on(oid));

        byte[] contents = Arrays.copyOfRange(encoding, 2, encoding.length);
        ASN1ObjectIdentifier fromContents = ASN1ObjectIdentifier.fromContents(contents);
        isTrue(label + "fromContents", fromContents.equals(valid) && Arrays.areEqual(encoding, fromContents.getEncoded()));

        ASN1ObjectIdentifier pooled = oid.intern();
        isTrue(label + "intern gives the valid encoding", pooled != oid && pooled.equals(oid)
            && Arrays.areEqual(valid.getEncoded(), pooled.getEncoded()));
        isTrue(label + "intern of the pooled instance", pooled.intern() == pooled);
        isTrue(label + "valid encoding parses to the pooled instance",
            ASN1ObjectIdentifier.getInstance(valid.getEncoded()) == pooled);

        ASN1ObjectIdentifier again = ASN1ObjectIdentifier.getInstance(encoding);
        isTrue(label + "invalid encoding is never pooled", again != pooled && again != oid
            && Arrays.areEqual(encoding, again.getEncoded()));
    }

    public static void main(
        String[] args)
    {
        ObjectIdentifierTest test = new ObjectIdentifierTest();
        TestResult result = test.perform();

        System.out.println(result);
    }
}
