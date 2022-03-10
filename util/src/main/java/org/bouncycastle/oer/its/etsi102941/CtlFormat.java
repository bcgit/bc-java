package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.its.etsi102941.basetypes.Version;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Time32;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.UINT8;

/**
 * CtlFormat ::= SEQUENCE {
 * version     Version,
 * nextUpdate  Time32,
 * isFullCtl   BOOLEAN,
 * ctlSequence INTEGER (0..255),
 * ctlCommands SEQUENCE OF CtlCommand,
 * ...
 * }
 */
public class CtlFormat
    extends ASN1Object
{

    private final Version version;
    private final Time32 nextUpdate;
    private final ASN1Boolean isFullCtl;
    private final UINT8 ctlSequence;
    private final SequenceOfCtlCommand ctlCommands;

    public CtlFormat(Version version, Time32 nextUpdate, ASN1Boolean isFullCtl, UINT8 ctlSequence, SequenceOfCtlCommand ctlCommands)
    {
        this.version = version;
        this.nextUpdate = nextUpdate;
        this.isFullCtl = isFullCtl;
        this.ctlSequence = ctlSequence;
        this.ctlCommands = ctlCommands;
    }

    protected CtlFormat(ASN1Sequence seq)
    {
        if (seq.size() != 5)
        {
            throw new IllegalArgumentException("expected sequence size of 5");
        }

        version = Version.getInstance(seq.getObjectAt(0));
        nextUpdate = Time32.getInstance(seq.getObjectAt(1));
        isFullCtl = ASN1Boolean.getInstance(seq.getObjectAt(2));
        ctlSequence = UINT8.getInstance(seq.getObjectAt(3));
        ctlCommands = SequenceOfCtlCommand.getInstance(seq.getObjectAt(4));

    }


    public static CtlFormat getInstance(Object o)
    {
        if (o instanceof CtlFormat)
        {
            return (CtlFormat)o;
        }
        if (o != null)
        {
            return new CtlFormat(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public Version getVersion()
    {
        return version;
    }

    public Time32 getNextUpdate()
    {
        return nextUpdate;
    }

    public ASN1Boolean getIsFullCtl()
    {
        return isFullCtl;
    }

    public UINT8 getCtlSequence()
    {
        return ctlSequence;
    }

    public SequenceOfCtlCommand getCtlCommands()
    {
        return ctlCommands;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{version, nextUpdate, isFullCtl, ctlSequence, ctlCommands});
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private Version version;
        private Time32 nextUpdate;
        private ASN1Boolean isFullCtl;
        private UINT8 ctlSequence;
        private SequenceOfCtlCommand ctlCommands;

        public Builder setVersion(Version version)
        {
            this.version = version;
            return this;
        }

        public Builder setNextUpdate(Time32 nextUpdate)
        {
            this.nextUpdate = nextUpdate;
            return this;
        }

        public Builder setIsFullCtl(ASN1Boolean isFullCtl)
        {
            this.isFullCtl = isFullCtl;
            return this;
        }

        public Builder setCtlSequence(UINT8 ctlSequence)
        {
            this.ctlSequence = ctlSequence;
            return this;
        }

        public Builder setCtlSequence(ASN1Integer ctlSequence)
        {
            this.ctlSequence = new UINT8(ctlSequence.getValue());
            return this;
        }

        public Builder setCtlCommands(SequenceOfCtlCommand ctlCommands)
        {
            this.ctlCommands = ctlCommands;
            return this;
        }

        public CtlFormat createCtlFormat()
        {
            return new CtlFormat(version, nextUpdate, isFullCtl, ctlSequence, ctlCommands);
        }

        public DeltaCtl createDeltaCtl()
        {
            if (isFullCtl != null && ASN1Boolean.TRUE.equals(isFullCtl))
            {
                throw new IllegalArgumentException("isFullCtl must be false for DeltaCtl");
                // exception for users, value hard coded by constructor.
            }
            return new DeltaCtl(version, nextUpdate, ctlSequence, ctlCommands);
        }

        public FullCtl createFullCtl()
        {
            return new FullCtl(version, nextUpdate, isFullCtl, ctlSequence, ctlCommands);
        }

        public ToBeSignedRcaCtl createToBeSignedRcaCtl()
        {
            return new ToBeSignedRcaCtl(version, nextUpdate, isFullCtl, ctlSequence, ctlCommands);
        }
    }

}
