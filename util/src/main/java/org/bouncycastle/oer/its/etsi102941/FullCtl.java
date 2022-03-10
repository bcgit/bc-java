package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.etsi102941.basetypes.Version;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Time32;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.UINT8;

public class FullCtl
    extends CtlFormat
{

    public FullCtl(Version version, Time32 nextUpdate, ASN1Boolean isFullCtl, UINT8 ctlSequence, SequenceOfCtlCommand ctlCommands)
    {
        super(version, nextUpdate, isFullCtl, ctlSequence, ctlCommands);
    }

    protected FullCtl(ASN1Sequence seq)
    {
        super(seq);
    }

    public static FullCtl getInstance(Object o)
    {
        if (o instanceof FullCtl)
        {
            return (FullCtl)o;
        }

        if (o != null)
        {
            return new FullCtl(ASN1Sequence.getInstance(o));
        }

        return null;
    }
}
