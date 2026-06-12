package org.bouncycastle.asn1.microsoft.test;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.microsoft.MicrosoftObjectIdentifiers;
import org.bouncycastle.asn1.microsoft.TimeStampRequest;
import org.bouncycastle.util.test.SimpleTest;

public class TimeStampRequestTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new TimeStampRequestTest());
    }

    public String getName()
    {
        return "TimeStampRequestTest";
    }

    public void performTest()
        throws Exception
    {
        ContentInfo content = new ContentInfo(CMSObjectIdentifiers.data,
            new DEROctetString(new byte[] { 1, 2, 3, 4 }));

        // convenience constructor - standard countersignature type, no attributes
        TimeStampRequest req = new TimeStampRequest(content);
        TimeStampRequest reqResult = TimeStampRequest.getInstance(req.getEncoded());

        isEquals("countersignatureType", MicrosoftObjectIdentifiers.microsoftTimeStampRequest,
            reqResult.getCountersignatureType());
        isTrue("attributes not null", reqResult.getAttributes() == null);
        isTrue("content", areEqual(content.getEncoded(), reqResult.getContent().getEncoded()));

        // full constructor, attributes present
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new Attribute(CMSAttributes.contentType, new DERSet(CMSObjectIdentifiers.data)));
        Attributes attributes = new Attributes(v);

        req = new TimeStampRequest(new ASN1ObjectIdentifier("1.2.3.4"), attributes, content);
        reqResult = TimeStampRequest.getInstance(req.getEncoded());

        isEquals("countersignatureType", new ASN1ObjectIdentifier("1.2.3.4"),
            reqResult.getCountersignatureType());
        isTrue("attributes", areEqual(attributes.getEncoded(), reqResult.getAttributes().getEncoded()));
        isTrue("content", areEqual(content.getEncoded(), reqResult.getContent().getEncoded()));

        isEquals("getInstance(same)", reqResult, TimeStampRequest.getInstance(reqResult));
        isTrue("getInstance(null)", TimeStampRequest.getInstance(null) == null);

        try
        {
            TimeStampRequest.getInstance(new DERSequence());
            fail("sequence length 0 accepted");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("exception message", "Bad sequence size: 0", e.getMessage());
        }

        ASN1EncodableVector big = new ASN1EncodableVector();
        big.add(MicrosoftObjectIdentifiers.microsoftTimeStampRequest);
        big.add(attributes);
        big.add(content);
        big.add(content);

        try
        {
            TimeStampRequest.getInstance(new DERSequence(big));
            fail("sequence length 4 accepted");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("exception message", "Bad sequence size: 4", e.getMessage());
        }
    }
}
