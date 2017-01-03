package org.bouncycastle.asn1.test;

import java.util.Date;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.cmc.CMCFailInfo;
import org.bouncycastle.asn1.cmc.CMCStatus;
import org.bouncycastle.asn1.cmc.CMCStatusInfo;
import org.bouncycastle.asn1.cmc.PendInfo;
import org.bouncycastle.util.test.SimpleTest;


public class CMCStatusInfoTest
    extends SimpleTest
{

    public static void main(String[] args)
    {
        runTest(new CMCStatusInfoTest());
    }

    public String getName()
    {
        return "CMCStatusInfoTest";
    }

    public void performTest()
        throws Exception
    {
        { // Without optional other info.

            CMCStatusInfo cmsInfo = new CMCStatusInfo(
                CMCStatus.confirmRequired,
                new DERSequence(new BodyPartID(10)),
                new DERUTF8String("Cats"));

            isEquals("Has other info", false, cmsInfo.hasOtherInfo());

            byte[] b = cmsInfo.getEncoded();
            CMCStatusInfo res = CMCStatusInfo.getInstance(b);

            // Same
            isEquals("CMCStatus with no optional part",cmsInfo, res);

            isEquals("Has other info", false, res.hasOtherInfo());

        }


        { // With optional info: PendInfo
            CMCStatusInfo cmsInfo = new CMCStatusInfo(
                CMCStatus.confirmRequired,
                new DERSequence(new BodyPartID(10)),
                new DERUTF8String("Cats"),
                CMCStatusInfo.OtherInfo.getInstance(PendInfo.getInstance(new DERSequence(new ASN1Encodable[]{
                    new DEROctetString("fish".getBytes()),
                    new DERGeneralizedTime(new Date())
                })))
            );

            isEquals("Must have other info", true, cmsInfo.hasOtherInfo());
            isEquals("Other is NOT fail info", false, cmsInfo.getOtherInfo().isFailInfo());

            byte[] b = cmsInfo.getEncoded();
            CMCStatusInfo res = CMCStatusInfo.getInstance(b);

            isEquals("With optional info: PendInfo",cmsInfo, res);

            isEquals("Must have other info", true, res.hasOtherInfo());
            isEquals("Other is NOT fail info", false, res.getOtherInfo().isFailInfo());
        }


        { // With optional info: CMCFailInfo
            CMCStatusInfo cmsInfo = new CMCStatusInfo(
                CMCStatus.confirmRequired,
                new DERSequence(new BodyPartID(10)),
                new DERUTF8String("Cats"),
                CMCStatusInfo.OtherInfo.getInstance(CMCFailInfo.authDataFail)
            );

            isEquals("Must have other info", true, cmsInfo.hasOtherInfo());
            isEquals("Other is fail info", true, cmsInfo.getOtherInfo().isFailInfo());

            byte[] b = cmsInfo.getEncoded();
            CMCStatusInfo res = CMCStatusInfo.getInstance(b);

            isEquals("With optional info: CMCFailInfo",cmsInfo, res);

            isEquals("Must have other info", true, res.hasOtherInfo());
            isEquals("Other is fail info", true, res.getOtherInfo().isFailInfo());
        }

    }
}
