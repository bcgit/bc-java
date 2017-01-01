package org.bouncycastle.asn1.test;


import java.io.ByteArrayInputStream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSet;

import org.bouncycastle.asn1.cmc.TaggedAttribute;
import org.bouncycastle.asn1.dvcs.DVCSObjectIdentifiers;
import org.bouncycastle.util.test.SimpleTest;


public class TaggedAttributeTest extends SimpleTest
{
    public String getName()
    {
        return "TaggedAttributeTest";
    }

    public void performTest()
        throws Exception
    {
        //
        // This creates and tests the various get instance  methods.
        //
        TaggedAttribute ta = new TaggedAttribute(new ASN1Integer(10L), DVCSObjectIdentifiers.id_cct_PKIData,new DERSet(new ASN1Encodable[]{new DERIA5String("Cats")}));
        byte[] d = ta.getEncoded();


        {
            TaggedAttribute res1 = TaggedAttribute.getInstance(d);
            isEquals(ta.getBodyPartID(), res1.getBodyPartID());
            isEquals(ta.getAttrType(), res1.getAttrType());
            isEquals(ta.getAttrValues().getObjectAt(0), res1.getAttrValues().getObjectAt(0));
        }


        {
            TaggedAttribute res1 = TaggedAttribute.getInstance(new ByteArrayInputStream(d));
            isEquals(ta.getBodyPartID(), res1.getBodyPartID());
            isEquals(ta.getAttrType(), res1.getAttrType());
            isEquals(ta.getAttrValues().getObjectAt(0), res1.getAttrValues().getObjectAt(0));
        }


        {
            TaggedAttribute res1 = TaggedAttribute.getInstance(new ASN1InputStream(new ByteArrayInputStream(d)));
            isEquals(ta.getBodyPartID(), res1.getBodyPartID());
            isEquals(ta.getAttrType(), res1.getAttrType());
            isEquals(ta.getAttrValues().getObjectAt(0), res1.getAttrValues().getObjectAt(0));
        }



    }

    public static void main(String[] args) throws Exception {
        runTest(new TaggedAttributeTest());
    }
}
