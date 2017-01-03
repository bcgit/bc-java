package org.bouncycastle.asn1.test;

import java.io.ByteArrayInputStream;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.cmc.CertificationRequest;
import org.bouncycastle.asn1.cmc.TaggedCertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;


public class TaggedCertificationRequestTest extends SimpleTest
{
    public static void main(String[] args) {
        runTest(new TaggedCertificationRequestTest());
    }

    public String getName()
    {
        return "TaggedCertificationRequestTest";
    }


    private static byte[]    req1 = Base64.decode(
        "MIHoMIGTAgEAMC4xDjAMBgNVBAMTBVRlc3QyMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNF"
            +   "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALlEt31Tzt2MlcOljvacJgzQVhmlMoqAOgqJ9Pgd3Gux"
            +   "Z7/WcIlgW4QCB7WZT21O1YoghwBhPDMcNGrHei9kHQkCAwEAAaAAMA0GCSqGSIb3DQEBBQUAA0EA"
            +   "NDEI4ecNtJ3uHwGGlitNFq9WxcoZ0djbQJ5hABMotav6gtqlrwKXY2evaIrsNwkJtNdwwH18aQDU"
            +   "KCjOuBL38Q==");


    public void performTest()
        throws Exception
    {

        ByteArrayInputStream bIn = new ByteArrayInputStream(req1);
        ASN1InputStream aIn = new ASN1InputStream(bIn);
        CertificationRequest    r = CertificationRequest.getInstance((ASN1Sequence)aIn.readObject());
        TaggedCertificationRequest tcr = new TaggedCertificationRequest(new BodyPartID(10L), r);

        byte[] b = tcr.getEncoded();
        TaggedCertificationRequest tcrResp = TaggedCertificationRequest.getInstance(b);

        isEquals(tcrResp,tcr);

    }
}
