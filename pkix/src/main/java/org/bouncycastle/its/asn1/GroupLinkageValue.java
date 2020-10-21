package org.bouncycastle.its.asn1;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class GroupLinkageValue extends ASN1Object
{
    private ASN1OctetString jValue;
    private ASN1OctetString value;


    public GroupLinkageValue getInstance(Object src) {
        if (src == null) {
            return null;
        } else if (src instanceof GroupLinkageValue) {
            return (GroupLinkageValue)src;
        } else if (src instanceof  ASN1Sequence) {
            if (((ASN1Sequence)src).size() != 2) {
                throw new IllegalStateException("expected sequence with jValue and value");
            }
            GroupLinkageValue glv = new GroupLinkageValue();
            glv.jValue = (ASN1OctetString)((ASN1Sequence)src).getObjectAt(0);
            glv.value = (ASN1OctetString)((ASN1Sequence)src).getObjectAt(1);
            return glv;
        } else {
            return getInstance(ASN1Sequence.getInstance(src));
        }
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector avec = new ASN1EncodableVector();
        avec.add(jValue);
        avec.add(value);
        return new DERSequence(avec);
    }


    public ASN1OctetString getjValue()
    {
        return jValue;
    }

    public void setjValue(ASN1OctetString jValue)
    {
        this.jValue = jValue;
    }

    public ASN1OctetString getValue()
    {
        return value;
    }

    public void setValue(ASN1OctetString value)
    {
        this.value = value;
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (o == null || getClass() != o.getClass())
        {
            return false;
        }
        if (!super.equals(o))
        {
            return false;
        }

        GroupLinkageValue that = (GroupLinkageValue)o;

        if (jValue != null ? !jValue.equals(that.jValue) : that.jValue != null)
        {
            return false;
        }
        return value != null ? value.equals(that.value) : that.value == null;
    }

    @Override
    public int hashCode()
    {
        int result = super.hashCode();
        result = 31 * result + (jValue != null ? jValue.hashCode() : 0);
        result = 31 * result + (value != null ? value.hashCode() : 0);
        return result;
    }
}
