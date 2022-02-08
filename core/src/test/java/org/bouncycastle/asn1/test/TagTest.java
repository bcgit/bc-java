package org.bouncycastle.asn1.test;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;


/**
 * X.690 test example
 */
public class TagTest
    extends SimpleTest
{
    byte[] longTagged = Base64.decode(
                  "ZSRzIp8gEEZFRENCQTk4NzY1NDMyMTCfIQwyMDA2MDQwMTEyMzSUCCAFERVz"
                + "A4kCAHEXGBkalAggBRcYGRqUCCAFZS6QAkRFkQlURUNITklLRVKSBQECAwQF"
                + "kxAREhMUFRYXGBkalAggBREVcwOJAgBxFxgZGpQIIAUXGBkalAggBWUukAJE"
                + "RZEJVEVDSE5JS0VSkgUBAgMEBZMQERITFBUWFxgZGpQIIAURFXMDiQIAcRcY"
                + "GRqUCCAFFxgZGpQIIAVlLpACREWRCVRFQ0hOSUtFUpIFAQIDBAWTEBESExQV"
                + "FhcYGRqUCCAFERVzA4kCAHEXGBkalAggBRcYGRqUCCAFFxgZGpQIIAUXGBka"
                + "lAg=");

    byte[] longAppSpecificTag = Hex.decode("5F610101");

    byte[] taggedInteger = Hex.decode("BF2203020101");

    public String getName()
    {
        return "Tag";
    }
    
    public void performTest()
        throws IOException
    {
        ASN1InputStream aIn = new ASN1InputStream(longTagged);

        ASN1TaggedObject app = (ASN1TaggedObject)aIn.readObject();
        if (!app.hasTag(BERTags.APPLICATION, 5))
        {
            fail("unexpected tag value found - not 5");
        }

        app = (ASN1TaggedObject)app.getExplicitBaseTagged();
        if (!app.hasTag(BERTags.APPLICATION, 19))
        {
            fail("unexpected tag value found - not 19");
        }

        ASN1Sequence seq = (ASN1Sequence)app.getBaseUniversal(false, BERTags.SEQUENCE);

        ASN1TaggedObject tagged = (ASN1TaggedObject)seq.getObjectAt(0);
        if (!tagged.hasContextTag(32))
        {
            fail("unexpected tag value found - not 32");
        }

        tagged = (ASN1TaggedObject)ASN1Primitive.fromByteArray(tagged.getEncoded());
        if (!tagged.hasContextTag(32))
        {
            fail("unexpected tag value found on recode - not 32");
        }

        tagged = (ASN1TaggedObject)seq.getObjectAt(1);
        if (!tagged.hasContextTag(33))
        {
            fail("unexpected tag value found - not 33");
        }

        tagged = (ASN1TaggedObject)ASN1Primitive.fromByteArray(tagged.getEncoded());
        if (!tagged.hasContextTag(33))
        {
            fail("unexpected tag value found on recode - not 33");
        }

        aIn = new ASN1InputStream(longAppSpecificTag);

        app = (ASN1TaggedObject)aIn.readObject();
        if (!app.hasTag(BERTags.APPLICATION, 97))
        {
            fail("incorrect tag number read");
        }

        app = (ASN1TaggedObject)ASN1Primitive.fromByteArray(app.getEncoded());
        if (!app.hasTag(BERTags.APPLICATION, 97))
        {
            fail("incorrect tag number read on recode");
        }

        SecureRandom sr = new SecureRandom();
        for (int i = 0; i < 100; ++i)
        {
            int testTag = sr.nextInt() >>> (1 + (sr.nextInt() >>> 1) % 26);
            app = new DERTaggedObject(false, BERTags.APPLICATION, testTag, new DEROctetString(new byte[]{ 1 }));
            app = (ASN1TaggedObject)ASN1Primitive.fromByteArray(app.getEncoded());

            if (!app.hasTag(BERTags.APPLICATION,  testTag))
            {
                fail("incorrect tag number read on recode (random test value: " + testTag + ")");
            }
        }

        tagged = new DERTaggedObject(false, 34, new DERTaggedObject(true, 1000, new ASN1Integer(1)));
        if (!areEqual(taggedInteger, tagged.getEncoded()))
        {
            fail("incorrect encoding for implicit explicit tagged integer");
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new TagTest());
    }
}
