package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmc.PopLinkWitnessV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.test.SimpleTest;


public class PopLinkWitnessV2Test
    extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new PopLinkWitnessV2Test());
    }

    public String getName()
    {
        return "PopLinkWitnessV2Test";
    }

    public void performTest()
        throws Exception
    {
        // Object identifiers real but not correct in this context.
        PopLinkWitnessV2 popLinkWitnessV2 = new PopLinkWitnessV2(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.bagtypes, new ASN1Integer(10L)),
            new AlgorithmIdentifier(PKCSObjectIdentifiers.crlTypes, new ASN1Integer(12L)),
            "cats".getBytes()
        );

        byte[] b = popLinkWitnessV2.getEncoded();
        PopLinkWitnessV2 popLinkWitnessV2Result = PopLinkWitnessV2.getInstance(b);

        isEquals(popLinkWitnessV2, popLinkWitnessV2Result);

        try
        {
            PopLinkWitnessV2.getInstance(new DERSequence());
            fail("Length must be 3");
        }
        catch (Throwable t)
        {
            isEquals(t.getClass(), IllegalArgumentException.class);
        }
    }
}
