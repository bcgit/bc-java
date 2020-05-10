package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.KMACwithSHAKE128_params;
import org.bouncycastle.asn1.nist.KMACwithSHAKE256_params;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;

public class KMACParamsTest
    extends SimpleTest
{
    public void performTest()
        throws Exception
    {
        isTrue(Arrays.areEqual(new KMACwithSHAKE128_params(256).getEncoded(), new DERSequence().getEncoded()));
        isTrue(Arrays.areEqual(new KMACwithSHAKE256_params(512).getEncoded(), new DERSequence().getEncoded()));

        isTrue(Arrays.areEqual(new KMACwithSHAKE128_params(512).getEncoded(), new DERSequence(new ASN1Integer(512)).getEncoded()));
        isTrue(Arrays.areEqual(new KMACwithSHAKE256_params(256).getEncoded(), new DERSequence(new ASN1Integer(256)).getEncoded()));

        isTrue(Arrays.areEqual(new KMACwithSHAKE128_params(512).getEncoded(), KMACwithSHAKE128_params.getInstance(new DERSequence(new ASN1Integer(512))).getEncoded()));
        isTrue(Arrays.areEqual(new KMACwithSHAKE256_params(256).getEncoded(), KMACwithSHAKE256_params.getInstance(new DERSequence(new ASN1Integer(256))).getEncoded()));

        byte[] customizationString = Strings.toByteArray("hello, world!");

        isTrue(Arrays.areEqual(new KMACwithSHAKE128_params(512, customizationString).getEncoded(), new DERSequence(
            new ASN1Encodable[] { new ASN1Integer(512), new DEROctetString(customizationString) }).getEncoded()));
        isTrue(Arrays.areEqual(new KMACwithSHAKE256_params(256, customizationString).getEncoded(), new DERSequence(
            new ASN1Encodable[] { new ASN1Integer(256), new DEROctetString(customizationString) }).getEncoded()));

        isTrue(Arrays.areEqual(new KMACwithSHAKE128_params(512, customizationString).getEncoded(),
            KMACwithSHAKE128_params.getInstance(
                new DERSequence(new ASN1Encodable[] { new ASN1Integer(512), new DEROctetString(customizationString) })).getEncoded()));
        isTrue(Arrays.areEqual(new KMACwithSHAKE256_params(256, customizationString).getEncoded(),
            KMACwithSHAKE256_params.getInstance(new DERSequence(
            new ASN1Encodable[] { new ASN1Integer(256), new DEROctetString(customizationString) })).getEncoded()));

        isTrue(Arrays.areEqual(new KMACwithSHAKE128_params(256, customizationString).getEncoded(), new DERSequence(
            new ASN1Encodable[] { new DEROctetString(customizationString) }).getEncoded()));
        isTrue(Arrays.areEqual(new KMACwithSHAKE256_params(512, customizationString).getEncoded(), new DERSequence(
            new ASN1Encodable[] { new DEROctetString(customizationString) }).getEncoded()));

        isTrue(Arrays.areEqual(new KMACwithSHAKE128_params(256, customizationString).getEncoded(),
            KMACwithSHAKE128_params.getInstance(
                new DERSequence(new ASN1Encodable[] { new DEROctetString(customizationString) })).getEncoded()));
        isTrue(Arrays.areEqual(new KMACwithSHAKE256_params(512, customizationString).getEncoded(),
            KMACwithSHAKE256_params.getInstance(new DERSequence(
            new ASN1Encodable[] { new DEROctetString(customizationString) })).getEncoded()));

        KMACwithSHAKE128_params p128 = new KMACwithSHAKE128_params(256, customizationString);
        isEquals(256, p128.getOutputLength());
        isTrue(Arrays.areEqual(customizationString, p128.getCustomizationString()));
        isTrue(p128 == KMACwithSHAKE128_params.getInstance(p128));

        KMACwithSHAKE256_params p256 = new KMACwithSHAKE256_params(512, customizationString);
        isEquals(512, p256.getOutputLength());
        isTrue(Arrays.areEqual(customizationString, p256.getCustomizationString()));
        isTrue(p256 == KMACwithSHAKE256_params.getInstance(p256));

        p128 = new KMACwithSHAKE128_params(512);
        isEquals(512, p128.getOutputLength());
        isTrue(Arrays.areEqual(new byte[0], p128.getCustomizationString()));

        p256 = new KMACwithSHAKE256_params(256);
        isEquals(256, p256.getOutputLength());
        isTrue(Arrays.areEqual(new byte[0], p256.getCustomizationString()));
    }

    public String getName()
    {
        return "KMACParams";
    }

    public static void main(
        String[]    args)
    {
        runTest(new KMACParamsTest());
    }
}
