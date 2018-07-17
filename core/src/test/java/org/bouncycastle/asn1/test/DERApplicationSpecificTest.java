package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1ApplicationSpecific;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERVisibleString;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class DERApplicationSpecificTest
    extends SimpleTest
{
    private static final byte[] impData = Hex.decode("430109");

    private static final byte[] certData = Hex.decode(
        "7F218201897F4E8201495F290100420E44454356434145504153533030317F49"
      + "81FD060A04007F00070202020202811CD7C134AA264366862A18302575D1D787"
      + "B09F075797DA89F57EC8C0FF821C68A5E62CA9CE6C1C299803A6C1530B514E18"
      + "2AD8B0042A59CAD29F43831C2580F63CCFE44138870713B1A92369E33E2135D2"
      + "66DBB372386C400B8439040D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C"
      + "1E6EFDEE12C07D58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D376"
      + "1402CD851CD7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A793"
      + "9F863904393EE8E06DB6C7F528F8B4260B49AA93309824D92CDB1807E5437EE2"
      + "E26E29B73A7111530FA86B350037CB9415E153704394463797139E148701015F"
      + "200E44454356434145504153533030317F4C0E060904007F0007030102015301"
      + "C15F25060007000400015F24060009000400015F37384CCF25C59F3612EEE188"
      + "75F6C5F2E2D21F0395683B532A26E4C189B71EFE659C3F26E0EB9AEAE9986310"
      + "7F9B0DADA16414FFA204516AEE2B");

    private final static byte[] sampleData = Hex.decode(
        "613280020780a106060456000104a203020101a305a103020101be80288006025101020109a080b2800a01000000000000000000");

    public String getName()
    {
        return "DERApplicationSpecific";
    }

    private void testTaggedObject()
                throws Exception
    {
        // boolean explicit, int tagNo, ASN1Encodable obj
        boolean explicit = false;

        // Type1 ::= VisibleString
        DERVisibleString type1 = new DERVisibleString("Jones");
        if (!Arrays.areEqual(Hex.decode("1A054A6F6E6573"), type1.getEncoded()))
        {
            fail("ERROR: expected value doesn't match!");
        }

        // Type2 ::= [APPLICATION 3] IMPLICIT Type1
        explicit = false;
        DERApplicationSpecific type2 = new DERApplicationSpecific(explicit, 3, type1);
        // type2.isConstructed()
        if (!Arrays.areEqual(Hex.decode("43054A6F6E6573"), type2.getEncoded()))
        {
            fail("ERROR: expected value doesn't match!");
        }

        // Type3 ::= [2] Type2
        explicit = true;
        DERTaggedObject type3 = new DERTaggedObject(explicit, 2, type2);
        if (!Arrays.areEqual(Hex.decode("A20743054A6F6E6573"), type3.getEncoded()))
        {
            fail("ERROR: expected value doesn't match!");
        }

        // Type4 ::= [APPLICATION 7] IMPLICIT Type3
        explicit = false;
        DERApplicationSpecific type4 = new DERApplicationSpecific(explicit, 7, type3);
        if (!Arrays.areEqual(Hex.decode("670743054A6F6E6573"), type4.getEncoded()))
        {
            fail("ERROR: expected value doesn't match!");
        }

        // Type5 ::= [2] IMPLICIT Type2
        explicit = false;
        DERTaggedObject type5 = new DERTaggedObject(explicit, 2, type2);
        // type5.isConstructed()
        if (!Arrays.areEqual(Hex.decode("82054A6F6E6573"), type5.getEncoded()))
        {
            fail("ERROR: expected value doesn't match!");
        }
    }

    public void performTest()
        throws Exception
    {
        testTaggedObject();

        ASN1ApplicationSpecific appSpec = (ASN1ApplicationSpecific)ASN1Primitive.fromByteArray(sampleData);

        if (1 != appSpec.getApplicationTag())
        {
            fail("wrong tag detected");
        }

        ASN1Integer value = new ASN1Integer(9);

        DERApplicationSpecific tagged = new DERApplicationSpecific(false, 3, value);

        if (!areEqual(impData, tagged.getEncoded()))
        {
            fail("implicit encoding failed");
        }

        ASN1Integer recVal = (ASN1Integer)tagged.getObject(BERTags.INTEGER);

        if (!value.equals(recVal))
        {
            fail("implicit read back failed");
        }

        ASN1ApplicationSpecific certObj = (ASN1ApplicationSpecific)ASN1Primitive.fromByteArray(certData);

        if (!certObj.isConstructed() || certObj.getApplicationTag() != 33)
        {
            fail("parsing of certificate data failed");
        }

        byte[] encoded = certObj.getEncoded(ASN1Encoding.DER);
    
        if (!Arrays.areEqual(certData, encoded))
        {
            fail("re-encoding of certificate data failed");
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new DERApplicationSpecificTest());
    }
}
