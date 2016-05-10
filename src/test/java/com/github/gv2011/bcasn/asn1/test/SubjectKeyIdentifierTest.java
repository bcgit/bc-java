package com.github.gv2011.bcasn.asn1.test;

import java.io.IOException;

import com.github.gv2011.bcasn.util.encoders.Base64;
import com.github.gv2011.bcasn.util.encoders.Hex;
import com.github.gv2011.bcasn.util.test.SimpleTest;

public class SubjectKeyIdentifierTest
    extends SimpleTest
{
    private static byte[] pubKeyInfo = Base64.decode(
        "MFgwCwYJKoZIhvcNAQEBA0kAMEYCQQC6wMMmHYMZszT/7bNFMn+gaZoiWJLVP8ODRuu1C2jeAe" +
        "QpxM+5Oe7PaN2GNy3nBE4EOYkB5pMJWA0y9n04FX8NAgED");

    private static byte[] shaID = Hex.decode("d8128a06d6c2feb0865994a2936e7b75b836a021");
    private static byte[] shaTruncID = Hex.decode("436e7b75b836a021");

    public String getName()
    {
        return "SubjectKeyIdentifier";
    }

    public void performTest()
        throws IOException
    {
//        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(pubKeyInfo));
//        SubjectKeyIdentifier ski = SubjectKeyIdentifier.createSHA1KeyIdentifier(pubInfo);
//
//        if (!Arrays.areEqual(shaID, ski.getKeyIdentifier()))
//        {
//            fail("SHA-1 ID does not match");
//        }
//
//        ski = SubjectKeyIdentifier.createTruncatedSHA1KeyIdentifier(pubInfo);
//
//        if (!Arrays.areEqual(shaTruncID, ski.getKeyIdentifier()))
//        {
//            fail("truncated SHA-1 ID does not match");
//        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new SubjectKeyIdentifierTest());
    }
}
