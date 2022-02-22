package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.OEROptional;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.GroupLinkageValue;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.IValue;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.LinkageValue;

/**
 * <pre>
 *     LinkageData ::= SEQUENCE {
 *         iCert IValue,
 *         linkage-value LinkageValue,
 *         group-linkage-value GroupLinkageValue OPTIONAL
 *     }
 * </pre>
 */
public class LinkageData
    extends ASN1Object
{
    private final IValue iCert;
    private final LinkageValue linkageValue;
    private final GroupLinkageValue groupLinkageValue;

    public LinkageData(IValue iCert, LinkageValue linkageValue, GroupLinkageValue groupLinkageValue)
    {
        this.iCert = iCert;
        this.linkageValue = linkageValue;
        this.groupLinkageValue = groupLinkageValue;
    }

    private LinkageData(ASN1Sequence seq)
    {
        if (seq.size() != 3)
        {
            throw new IllegalArgumentException("expected sequence size of 3");
        }

        this.iCert = IValue.getInstance(seq.getObjectAt(0));
        this.linkageValue = LinkageValue.getInstance(seq.getObjectAt(1));
        this.groupLinkageValue = OEROptional.getValue(GroupLinkageValue.class, seq.getObjectAt(2));
    }

    public static LinkageData getInstance(Object src)
    {
        if (src instanceof LinkageData)
        {
            return (LinkageData)src;
        }
        else if (src != null)
        {
            return new LinkageData(ASN1Sequence.getInstance(src));
        }

        return null;
    }

    public IValue getICert()
    {
        return iCert;
    }

    public LinkageValue getLinkageValue()
    {
        return linkageValue;
    }

    public GroupLinkageValue getGroupLinkageValue()
    {
        return groupLinkageValue;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{iCert, linkageValue, OEROptional.getInstance(groupLinkageValue)});
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private IValue iCert;
        private LinkageValue linkageValue;
        private GroupLinkageValue groupLinkageValue;

        public Builder setICert(IValue iCert)
        {
            this.iCert = iCert;
            return this;
        }

        public Builder setLinkageValue(LinkageValue linkageValue)
        {
            this.linkageValue = linkageValue;
            return this;
        }

        public Builder setGroupLinkageValue(GroupLinkageValue groupLinkageValue)
        {
            this.groupLinkageValue = groupLinkageValue;
            return this;
        }

        public LinkageData createLinkageData()
        {
            return new LinkageData(iCert, linkageValue, groupLinkageValue);
        }
    }
}
