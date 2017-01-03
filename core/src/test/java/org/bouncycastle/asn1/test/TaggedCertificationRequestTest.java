package org.bouncycastle.asn1.test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.cmc.TaggedCertificationRequest;
import org.bouncycastle.asn1.oiw.ElGamalParameter;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
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
        CertificationRequest    r = new CertificationRequest((ASN1Sequence)aIn.readObject());
        TaggedCertificationRequest tcr = new TaggedCertificationRequest(new BodyPartID(10L), r);

        byte[] b = tcr.getEncoded();
        TaggedCertificationRequest tcrResp = TaggedCertificationRequest.getInstance(b);

        isEquals(tcrResp,tcr);

    }
}
