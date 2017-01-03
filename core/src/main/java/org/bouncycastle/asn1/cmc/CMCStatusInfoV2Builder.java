package org.bouncycastle.asn1.cmc;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

public class CMCStatusInfoV2Builder
{
    private final CMCStatus cMCStatus;
    private final ASN1Sequence bodyList;

    private DERUTF8String statusString;
    private OtherStatusInfo otherInfo;

    public CMCStatusInfoV2Builder(CMCStatus cMCStatus, BodyPartID bodyPartID)
    {
        this.cMCStatus = cMCStatus;
        this.bodyList = new DERSequence(bodyPartID);
    }

    public CMCStatusInfoV2Builder(CMCStatus cMCStatus, BodyPartID[] bodyList)
    {
        this.cMCStatus = cMCStatus;
        this.bodyList = new DERSequence(bodyList);
    }

    public CMCStatusInfoV2Builder setStatusString(String statusString)
    {
        this.statusString = new DERUTF8String(statusString);

        return this;
    }

    public CMCStatusInfoV2Builder setOtherInfo(CMCFailInfo failInfo)
    {
        this.otherInfo = new OtherStatusInfo(failInfo);

        return this;
    }

    public CMCStatusInfoV2Builder setOtherInfo(ExtendedFailInfo extendedFailInfo)
    {
        this.otherInfo = new OtherStatusInfo(extendedFailInfo);

        return this;
    }

    public CMCStatusInfoV2Builder setOtherInfo(PendInfo pendInfo)
    {
        this.otherInfo = new OtherStatusInfo(pendInfo);

        return this;
    }

    public CMCStatusInfoV2 build()
    {
        return new CMCStatusInfoV2(cMCStatus, bodyList, statusString, otherInfo);
    }
}
