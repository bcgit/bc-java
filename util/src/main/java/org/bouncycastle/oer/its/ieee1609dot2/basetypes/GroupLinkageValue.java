package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.oer.its.ItsUtils;
import org.bouncycastle.util.Arrays;

/**
 * <pre>
 *     GroupLinkageValue ::= SEQUENCE {
 *         jValue OCTET STRING (SIZE(4))
 *         value OCTET STRING (SIZE(9))
 *     }
 * </pre>
 */
public class GroupLinkageValue
    extends ASN1Object
{
    private final ASN1OctetString jValue;
    private final ASN1OctetString value;

    private GroupLinkageValue(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }

        jValue = ASN1OctetString.getInstance(seq.getObjectAt(0));
        value = ASN1OctetString.getInstance(seq.getObjectAt(1));
        assertValues();
    }

    public GroupLinkageValue(ASN1OctetString jValue, ASN1OctetString value)
    {
        this.jValue = jValue;
        this.value = value;
        assertValues();
    }

    private void assertValues()
    {
        if (jValue == null || jValue.getOctets().length != 4)
        {
            throw new IllegalArgumentException("jValue is null or not four bytes long");
        }

        if (value == null || value.getOctets().length != 9)
        {
            throw new IllegalArgumentException("value is null or not nine bytes long");
        }

    }

    public static GroupLinkageValue getInstance(Object src)
    {
        if (src instanceof GroupLinkageValue)
        {
            return (GroupLinkageValue)src;
        }
        else if (src != null)
        {
            return new GroupLinkageValue(ASN1Sequence.getInstance(src));
        }

        return null;
    }

    public ASN1OctetString getJValue()
    {
        return jValue;
    }

    public ASN1OctetString getValue()
    {
        return value;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return ItsUtils.toSequence(jValue, value);
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private ASN1OctetString jValue;
        private ASN1OctetString value;

        public Builder setJValue(ASN1OctetString jValue)
        {
            this.jValue = jValue;
            return this;
        }

        public Builder setJValue(byte[] jValue)
        {
            return setJValue(new DEROctetString(Arrays.clone(jValue)));
        }

        public Builder setValue(ASN1OctetString value)
        {
            this.value = value;
            return this;
        }

        public Builder setValue(byte[] value)
        {
            return setValue(new DEROctetString(Arrays.clone(value)));
        }

        public GroupLinkageValue createGroupLinkageValue()
        {
            return new GroupLinkageValue(jValue, value);
        }

    }

}
