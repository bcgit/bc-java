package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x509.EDIPartyName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class GeneralNameTest
    extends SimpleTest
{
    private static final byte[] ipv4 = Hex.decode("87040a090800");
    private static final byte[] ipv4WithMask1 = Hex.decode("87080a090800ffffff00");
    private static final byte[] ipv4WithMask2 = Hex.decode("87080a090800ffff8000");
    private static final byte[] ipv4WithMask3 = Hex.decode("87080a090800ffffc000");

    private static final byte[] ipv6a = Hex.decode("871020010db885a308d313198a2e03707334");
    private static final byte[] ipv6b = Hex.decode("871020010db885a3000013198a2e03707334");
    private static final byte[] ipv6c = Hex.decode("871000000000000000000000000000000001");
    private static final byte[] ipv6d = Hex.decode("871020010db885a3000000008a2e03707334");
    private static final byte[] ipv6e = Hex.decode("871020010db885a3000000008a2e0a090800");
    private static final byte[] ipv6f = Hex.decode("872020010db885a3000000008a2e0a090800ffffffffffff00000000000000000000");
    private static final byte[] ipv6g = Hex.decode("872020010db885a3000000008a2e0a090800ffffffffffffffffffffffffffffffff");
    private static final byte[] ipv6h = Hex.decode("872020010db885a300000000000000000000ffffffffffff00000000000000000000");
    private static final byte[] ipv6i = Hex.decode("872020010db885a300000000000000000000fffffffffffe00000000000000000000");
    private static final byte[] ipv6j = Hex.decode("872020010db885a300000000000000000000ffffffffffff80000000000000000000");

    /**
     * RFC 5280 sec. 4.2.1.6:
     * <pre>
     * EDIPartyName ::= SEQUENCE {
     *      nameAssigner            [0]     DirectoryString OPTIONAL,
     *      partyName               [1]     DirectoryString }
     * </pre>
     * Both tags are explicit, despite the module's IMPLICIT TAGS, because DirectoryString is a
     * CHOICE and X.680 does not permit implicitly tagging one. The decoder had this right but
     * toASN1Primitive emitted the DirectoryStrings bare, so an EDIPartyName built through the
     * constructor could not parse its own encoding, and neither could GeneralName - which since
     * the type was added validates the ediPartyName alternative through it (github #2380).
     */
    private void ediPartyNameTest()
        throws Exception
    {
        // SEQUENCE { [0] { UTF8String "assigner" }, [1] { UTF8String "party" } }
        byte[] expected = Hex.decode("3015a00a0c0861737369676e6572a1070c057061727479");

        EDIPartyName both = new EDIPartyName(new DirectoryString("assigner"), new DirectoryString("party"));
        isTrue("EDIPartyName encoding not as RFC 5280", Arrays.areEqual(expected, both.getEncoded(ASN1Encoding.DER)));

        EDIPartyName decoded = EDIPartyName.getInstance(both.getEncoded(ASN1Encoding.DER));
        isEquals("assigner", decoded.getNameAssigner().getString());
        isEquals("party", decoded.getPartyName().getString());

        // nameAssigner is OPTIONAL; partyName keeps its [1] tag either way
        byte[] partyOnly = Hex.decode("3009a1070c057061727479");
        EDIPartyName one = new EDIPartyName(null, new DirectoryString("party"));
        isTrue("optional nameAssigner encoding wrong", Arrays.areEqual(partyOnly, one.getEncoded(ASN1Encoding.DER)));

        EDIPartyName decodedOne = EDIPartyName.getInstance(one.getEncoded(ASN1Encoding.DER));
        isTrue("nameAssigner should be absent", null == decodedOne.getNameAssigner());
        isEquals("party", decodedOne.getPartyName().getString());

        // and the GeneralName path that validates the alternative
        GeneralName gn = GeneralName.getInstance(
            new DERTaggedObject(false, GeneralName.ediPartyName, ASN1Primitive.fromByteArray(expected)));
        isEquals(GeneralName.ediPartyName, gn.getTagNo());

        // an untagged sequence remains a decode failure - the type is not read leniently
        try
        {
            EDIPartyName.getInstance(Hex.decode("30110c0861737369676e65720c057061727479"));
            fail("untagged EDIPartyName accepted");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    public String getName()
    {
        return "GeneralName";
    }

    public void performTest()
        throws Exception
    {
        ediPartyNameTest();

        GeneralName nm = new GeneralName(GeneralName.iPAddress, "10.9.8.0");
        if (!Arrays.areEqual(nm.getEncoded(), ipv4))
        {
            fail("ipv4 encoding failed");
        }

        nm = new GeneralName(GeneralName.iPAddress, "10.9.8.0/255.255.255.0");
        if (!Arrays.areEqual(nm.getEncoded(), ipv4WithMask1))
        {
            fail("ipv4 with netmask 1 encoding failed");
        }

        nm = new GeneralName(GeneralName.iPAddress, "10.9.8.0/24");
        if (!Arrays.areEqual(nm.getEncoded(), ipv4WithMask1))
        {
            fail("ipv4 with netmask 2 encoding failed");
        }

        nm = new GeneralName(GeneralName.iPAddress, "10.9.8.0/255.255.128.0");
        if (!Arrays.areEqual(nm.getEncoded(), ipv4WithMask2))
        {
            fail("ipv4 with netmask 3a encoding failed");
        }

        nm = new GeneralName(GeneralName.iPAddress, "10.9.8.0/17");
        if (!Arrays.areEqual(nm.getEncoded(), ipv4WithMask2))
        {
            fail("ipv4 with netmask 3b encoding failed");
        }

        nm = new GeneralName(GeneralName.iPAddress, "10.9.8.0/255.255.192.0");
        if (!Arrays.areEqual(nm.getEncoded(), ipv4WithMask3))
        {
            fail("ipv4 with netmask 3a encoding failed");
        }

        nm = new GeneralName(GeneralName.iPAddress, "10.9.8.0/18");
        if (!Arrays.areEqual(nm.getEncoded(), ipv4WithMask3))
        {
            fail("ipv4 with netmask 3b encoding failed");
        }

        nm = new GeneralName(GeneralName.iPAddress, "2001:0db8:85a3:08d3:1319:8a2e:0370:7334");
        if (!Arrays.areEqual(nm.getEncoded(), ipv6a))
        {
            fail("ipv6 with netmask encoding failed");
        }

        nm = new GeneralName(GeneralName.iPAddress, "2001:0db8:85a3::1319:8a2e:0370:7334");
        if (!Arrays.areEqual(nm.getEncoded(), ipv6b))
        {
            fail("ipv6b encoding failed");
        }

        nm = new GeneralName(GeneralName.iPAddress, "::1");
        if (!Arrays.areEqual(nm.getEncoded(), ipv6c))
        {
            fail("ipv6c failed");
        }

        nm = new GeneralName(GeneralName.iPAddress, "2001:0db8:85a3::8a2e:0370:7334");
        if (!Arrays.areEqual(nm.getEncoded(), ipv6d))
        {
            fail("ipv6d failed");
        }

        nm = new GeneralName(GeneralName.iPAddress, "2001:0db8:85a3::8a2e:10.9.8.0");
        if (!Arrays.areEqual(nm.getEncoded(), ipv6e))
        {
            fail("ipv6e failed");
        }

        nm = new GeneralName(GeneralName.iPAddress, "2001:0db8:85a3::8a2e:10.9.8.0/ffff:ffff:ffff::0000");
        if (!Arrays.areEqual(nm.getEncoded(), ipv6f))
        {
            fail("ipv6f failed");
        }

        nm = new GeneralName(GeneralName.iPAddress, "2001:0db8:85a3::8a2e:10.9.8.0/128");
        if (!Arrays.areEqual(nm.getEncoded(), ipv6g))
        {
            fail("ipv6g failed");
        }

        nm = new GeneralName(GeneralName.iPAddress, "2001:0db8:85a3::/48");
        if (!Arrays.areEqual(nm.getEncoded(), ipv6h))
        {
            fail("ipv6h failed");
        }

        nm = new GeneralName(GeneralName.iPAddress, "2001:0db8:85a3::/47");
        if (!Arrays.areEqual(nm.getEncoded(), ipv6i))
        {
            fail("ipv6i failed");
        }

        nm = new GeneralName(GeneralName.iPAddress, "2001:0db8:85a3::/49");
        if (!Arrays.areEqual(nm.getEncoded(), ipv6j))
        {
            fail("ipv6j failed");
        }

        GeneralNamesBuilder genNamesBuilder = new GeneralNamesBuilder();

        GeneralName name1 = new GeneralName(GeneralName.iPAddress, "2001:0db8:85a3::8a2e:0370:7334");

        genNamesBuilder.addName(name1);

        if (!genNamesBuilder.build().equals(new GeneralNames(name1)))
        {
            fail("single build failed");
        }

        GeneralName nm1 = new GeneralName(GeneralName.iPAddress, "2001:0db8:85a3::/48");
        GeneralName nm2 = new GeneralName(GeneralName.iPAddress, "2001:0db8:85a3::/47");
        GeneralName nm3 = new GeneralName(GeneralName.iPAddress, "2001:0db8:85a3::/49");

        genNamesBuilder = new GeneralNamesBuilder();

        genNamesBuilder.addName(name1);

        genNamesBuilder.addNames(new GeneralNames(new GeneralName[]{nm1, nm2}));

        genNamesBuilder.addName(nm3);

        if (!genNamesBuilder.build().equals(new GeneralNames(new GeneralName[] { name1, nm1, nm2, nm3 })))
        {
            fail("multi build failed");
        }
    }

    public static void main(
        String[] args)
    {
        runTest(new GeneralNameTest());
    }
}
