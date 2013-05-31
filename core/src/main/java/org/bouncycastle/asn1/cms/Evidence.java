package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;

public class Evidence
    extends ASN1Object
    implements ASN1Choice
{
    private TimeStampTokenEvidence tstEvidence;

    public Evidence(TimeStampTokenEvidence tstEvidence)
    {
        this.tstEvidence = tstEvidence;
    }

    private Evidence(ASN1TaggedObject tagged)
    {
        if (tagged.getTagNo() == 0)
        {
            this.tstEvidence = TimeStampTokenEvidence.getInstance(tagged, false);
        }
    }

    public static Evidence getInstance(Object obj)
    {
        if (obj == null || obj instanceof Evidence)
        {
            return (Evidence)obj;
        }
        else if (obj instanceof ASN1TaggedObject)
        {
            return new Evidence(ASN1TaggedObject.getInstance(obj));
        }

        throw new IllegalArgumentException("unknown object in getInstance");
    }

    public TimeStampTokenEvidence getTstEvidence()
    {
        return tstEvidence;
    }

    public ASN1Primitive toASN1Primitive()
    {
       if (tstEvidence != null)
       {
           return new DERTaggedObject(false, 0, tstEvidence);
       }

       return null;
    }
}
