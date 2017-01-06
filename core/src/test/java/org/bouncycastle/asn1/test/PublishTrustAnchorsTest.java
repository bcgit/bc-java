package org.bouncycastle.asn1.test;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmc.PublishTrustAnchors;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.test.SimpleTest;


public class PublishTrustAnchorsTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new PublishTrustAnchorsTest());
    }

    public String getName()
    {
        return "PublishTrustAnchorsTest";
    }

    public void performTest()
        throws Exception
    {
        PublishTrustAnchors publishTrustAnchors = new PublishTrustAnchors(
            new BigInteger("10"), new AlgorithmIdentifier(PKCSObjectIdentifiers.crlTypes,
            new ASN1Integer(5L)), new byte[][]{"cats".getBytes()});

        byte[] b = publishTrustAnchors.getEncoded();

        PublishTrustAnchors publishTrustAnchorsResult = PublishTrustAnchors.getInstance(b);

        isEquals("seqNumber", publishTrustAnchors.getSeqNumber(), publishTrustAnchorsResult.getSeqNumber());
        isEquals("hashAlgorithm", publishTrustAnchors.getHashAlgorithm(), publishTrustAnchorsResult.getHashAlgorithm());
        isTrue("anchorHashes", areEqual(publishTrustAnchors.getAnchorHashes(), publishTrustAnchorsResult.getAnchorHashes()));

        try
        {
            PublishTrustAnchors.getInstance(new DERSequence());
            fail("Sequence must be 3");
        }
        catch (Throwable t)
        {
            isEquals("Expect IllegalArgumentException", t.getClass(), IllegalArgumentException.class);
        }
    }
}
