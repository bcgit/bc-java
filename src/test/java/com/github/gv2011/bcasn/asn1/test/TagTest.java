package com.github.gv2011.bcasn.asn1.test;

import java.io.IOException;
import java.security.SecureRandom;

import com.github.gv2011.bcasn.asn1.ASN1InputStream;
import com.github.gv2011.bcasn.asn1.ASN1Primitive;
import com.github.gv2011.bcasn.asn1.ASN1TaggedObject;
import com.github.gv2011.bcasn.asn1.DERApplicationSpecific;
import com.github.gv2011.bcasn.util.encoders.Base64;
import com.github.gv2011.bcasn.util.encoders.Hex;
import com.github.gv2011.bcasn.util.test.SimpleTest;


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

    public String getName()
    {
        return "Tag";
    }
    
    public void performTest()
        throws IOException
    {
        ASN1InputStream aIn = new ASN1InputStream(longTagged);

        DERApplicationSpecific app = (DERApplicationSpecific)aIn.readObject();
        
        aIn = new ASN1InputStream(app.getContents());

        app = (DERApplicationSpecific)aIn.readObject();

        aIn = new ASN1InputStream(app.getContents());

        ASN1TaggedObject tagged = (ASN1TaggedObject)aIn.readObject();

        if (tagged.getTagNo() != 32)
        {
            fail("unexpected tag value found - not 32");
        }

        tagged = (ASN1TaggedObject)ASN1Primitive.fromByteArray(tagged.getEncoded());

        if (tagged.getTagNo() != 32)
        {
            fail("unexpected tag value found on recode - not 32");
        }

        tagged = (ASN1TaggedObject)aIn.readObject();

        if (tagged.getTagNo() != 33)
        {
            fail("unexpected tag value found - not 33");
        }

        tagged = (ASN1TaggedObject)ASN1Primitive.fromByteArray(tagged.getEncoded());

        if (tagged.getTagNo() != 33)
        {
            fail("unexpected tag value found on recode - not 33");
        }

        aIn = new ASN1InputStream(longAppSpecificTag);

        app = (DERApplicationSpecific)aIn.readObject();

        if (app.getApplicationTag() != 97)
        {
            fail("incorrect tag number read");
        }

        app = (DERApplicationSpecific)ASN1Primitive.fromByteArray(app.getEncoded());

        if (app.getApplicationTag() != 97)
        {
            fail("incorrect tag number read on recode");
        }

        SecureRandom sr = new SecureRandom();
        for (int i = 0; i < 100; ++i)
        {
            int testTag = sr.nextInt() >>> (1 + (sr.nextInt() >>> 1) % 26);
            app = new DERApplicationSpecific(testTag, new byte[]{ 1 });
            app = (DERApplicationSpecific)ASN1Primitive.fromByteArray(app.getEncoded());

            if (app.getApplicationTag() != testTag)
            {
                fail("incorrect tag number read on recode (random test value: " + testTag + ")");
            }
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new TagTest());
    }
}
