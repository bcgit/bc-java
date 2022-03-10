package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.its.etsi102941.basetypes.Version;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Time32;

/**
 * ToBeSignedCrl ::= SEQUENCE {
 * version    Version,
 * thisUpdate Time32,
 * nextUpdate Time32,
 * entries SEQUENCE OF CrlEntry,
 * ...
 * }
 */
public class ToBeSignedCrl
    extends ASN1Object
{

    private final Version version;
    private final Time32 thisUpdate;
    private final Time32 nextUpdate;
    private final SequenceOfCrlEntry entries;

    public ToBeSignedCrl(Version version, Time32 thisUpdate, Time32 nextUpdate, SequenceOfCrlEntry entries)
    {
        this.version = version;
        this.thisUpdate = thisUpdate;
        this.nextUpdate = nextUpdate;
        this.entries = entries;
    }

    private ToBeSignedCrl(ASN1Sequence sequence)
    {
        if (sequence.size() != 4)
        {
            throw new IllegalArgumentException("expected sequence size of 4");
        }

        version = Version.getInstance(sequence.getObjectAt(0));
        thisUpdate = Time32.getInstance(sequence.getObjectAt(1));
        nextUpdate = Time32.getInstance(sequence.getObjectAt(2));
        entries = SequenceOfCrlEntry.getInstance(sequence.getObjectAt(3));

    }

    public static ToBeSignedCrl getInstance(Object o)
    {
        if (o instanceof ToBeSignedCrl)
        {
            return (ToBeSignedCrl)o;
        }
        if (o != null)
        {
            return new ToBeSignedCrl(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public Version getVersion()
    {
        return version;
    }

    public Time32 getThisUpdate()
    {
        return thisUpdate;
    }

    public Time32 getNextUpdate()
    {
        return nextUpdate;
    }

    public SequenceOfCrlEntry getEntries()
    {
        return entries;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{version, thisUpdate, nextUpdate, entries});
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private Version version;
        private Time32 thisUpdate;
        private Time32 nextUpdate;
        private SequenceOfCrlEntry entries;

        public Builder setVersion(Version version)
        {
            this.version = version;
            return this;
        }

        public Builder setThisUpdate(Time32 thisUpdate)
        {
            this.thisUpdate = thisUpdate;
            return this;
        }

        public Builder setNextUpdate(Time32 nextUpdate)
        {
            this.nextUpdate = nextUpdate;
            return this;
        }

        public Builder setEntries(SequenceOfCrlEntry entries)
        {
            this.entries = entries;
            return this;
        }

        public ToBeSignedCrl createToBeSignedCrl()
        {
            return new ToBeSignedCrl(version, thisUpdate, nextUpdate, entries);
        }

    }

}
