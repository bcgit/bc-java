package org.bouncycastle.asn1.test;


import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.cmc.CertificationRequest;
import org.bouncycastle.asn1.cmc.EncryptedPOP;
import org.bouncycastle.asn1.cmc.TaggedCertificationRequest;
import org.bouncycastle.asn1.cmc.TaggedRequest;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

public class EncryptedPOPTest
    extends SimpleTest
{
    public String getName()
    {
        return "EncryptedPOPTest";
    }

    private byte[] req1 = Base64.decode(
        "MIHoMIGTAgEAMC4xDjAMBgNVBAMTBVRlc3QyMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNF"
            + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALlEt31Tzt2MlcOljvacJgzQVhmlMoqAOgqJ9Pgd3Gux"
            + "Z7/WcIlgW4QCB7WZT21O1YoghwBhPDMcNGrHei9kHQkCAwEAAaAAMA0GCSqGSIb3DQEBBQUAA0EA"
            + "NDEI4ecNtJ3uHwGGlitNFq9WxcoZ0djbQJ5hABMotav6gtqlrwKXY2evaIrsNwkJtNdwwH18aQDU"
            + "KCjOuBL38Q==");

    public void performTest()
        throws Exception
    {
        // All Object Identifiers are not real!
        TaggedRequest taggedRequest = new TaggedRequest(new TaggedCertificationRequest(new BodyPartID(10L), CertificationRequest.getInstance(req1)));
        ContentInfo cms = new ContentInfo(new ASN1ObjectIdentifier("1.2.3"), new ASN1Integer(12L));
        AlgorithmIdentifier thePopID = new AlgorithmIdentifier(new ASN1ObjectIdentifier("2.2.5.2"));
        AlgorithmIdentifier whitenessID = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.5.2.5"));
        byte[] whiteness = "Fish and Chips".getBytes();

        EncryptedPOP ep = new EncryptedPOP(taggedRequest, cms, thePopID, whitenessID, whiteness);
        byte[] b = ep.getEncoded();
        EncryptedPOP epResult = EncryptedPOP.getInstance(b);

        isEquals("TaggedRequest", epResult.getRequest(), taggedRequest);
        isEquals("ContentInfo (cms)", epResult.getCms(), cms);
        isEquals("Pop Algorithm ID", epResult.getThePOPAlgID(), thePopID);
        isEquals("Whiteness ID", epResult.getWitnessAlgID(), whitenessID);
        isTrue("Whiteness", areEqual(epResult.getWitness(), whiteness));

        // Test sequence length

        try
        {
            EncryptedPOP.getInstance(new DERSequence(new ASN1Integer(1L)));
            fail("Sequence must be 5 items long.");
        }
        catch (Throwable t)
        {
            isEquals(t.getClass(), IllegalArgumentException.class);
        }
    }

    public static void main(String[] args)
    {
        runTest(new EncryptedPOPTest());
    }
}
