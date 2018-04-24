package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.cmc.OtherMsg;
import org.bouncycastle.asn1.cmc.PKIResponse;
import org.bouncycastle.asn1.cmc.TaggedAttribute;
import org.bouncycastle.asn1.cmc.TaggedContentInfo;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.util.test.SimpleTest;


public class PKIResponseTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new PKIResponseTest());
    }

    public String getName()
    {
        return "PKIResponseTest";
    }

    public void performTest()
        throws Exception
    {
        PKIResponse pkiResponse = PKIResponse.getInstance(new DERSequence(new ASN1Encodable[]{
            new DERSequence(new TaggedAttribute(new BodyPartID(10L), PKCSObjectIdentifiers.bagtypes, new DERSet())),
            new DERSequence(new TaggedContentInfo(new BodyPartID(12L), new ContentInfo(PKCSObjectIdentifiers.id_aa, new ASN1Integer(10L)))),
            new DERSequence(new OtherMsg(new BodyPartID(12), PKCSObjectIdentifiers.id_aa_msgSigDigest, new DERUTF8String("foo")))
        }));

        byte[] b = pkiResponse.getEncoded();

        PKIResponse pkiResponseResult = PKIResponse.getInstance(b);

        isEquals(pkiResponse, pkiResponseResult);

    }
}
