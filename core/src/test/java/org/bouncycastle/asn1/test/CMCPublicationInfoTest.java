package org.bouncycastle.asn1.test;


import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmc.CMCPublicationInfo;
import org.bouncycastle.asn1.crmf.PKIPublicationInfo;
import org.bouncycastle.asn1.crmf.SinglePubInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.test.SimpleTest;

public class CMCPublicationInfoTest
    extends SimpleTest
{

    public void performTest()
        throws Exception
    {
        SecureRandom secureRandom = new SecureRandom();

        //
        // Test encode and decode.
        //

        // Not a real AlgorithmIdentifier
        AlgorithmIdentifier testIA = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.1.2.3"), DERNull.INSTANCE);
        byte[][] hashes = new byte[5][64];
        for(int i =0; i<hashes.length; i++) {
            secureRandom.nextBytes(hashes[i]);
        }

        PKIPublicationInfo pinfo = new PKIPublicationInfo(new SinglePubInfo(SinglePubInfo.dontCare, null));

        CMCPublicationInfo cmcPublicationInfo = new CMCPublicationInfo(testIA,hashes,pinfo);
        byte[] b = cmcPublicationInfo.getEncoded();
        CMCPublicationInfo resCmcPublicationInfo = CMCPublicationInfo.getInstance(b);

        isEquals(resCmcPublicationInfo,cmcPublicationInfo);

        //
        // Test fail on small sequence.
        //

        try
        {
            CMCPublicationInfo.getInstance(new DERSequence(new ASN1Encodable[]{testIA}));
            fail("Expecting exception.");
        } catch (Exception t) {
            isEquals("Wrong exception: "+t.getMessage(), t.getClass(), IllegalArgumentException.class);
        }

    }

    public String getName()
    {
        return "CMCPublicationInfo";
    }

    public static void main(String[] args) {
        runTest(new CMCPublicationInfoTest());
    }

}
