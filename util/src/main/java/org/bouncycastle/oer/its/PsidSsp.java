package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

public class PsidSsp
    extends ASN1Object
{
    private final Psid psid;
    private final ServiceSpecificPermissions ssp;

    public PsidSsp(Psid psid, ServiceSpecificPermissions ssp)
    {
        this.psid = psid;
        this.ssp = ssp;
    }

    public static PsidSsp getInstance(Object nextElement)
    {
        if (nextElement instanceof PsidSsp)
        {
            return (PsidSsp)nextElement;
        }

        ASN1Sequence seq = ASN1Sequence.getInstance(nextElement);
        return new Builder()
            .setPsid(Psid.getInstance(seq.getObjectAt(0)))
            .setSsp(ServiceSpecificPermissions.getInstance(seq.getObjectAt(1)))
            .createPsidSsp();
    }

    public Psid getPsid()
    {
        return psid;
    }

    public ServiceSpecificPermissions getSsp()
    {
        return ssp;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return Utils.toSequence(psid, ssp);
    }

    public static class Builder
    {

        private Psid psid;
        private ServiceSpecificPermissions ssp;

        public Builder setPsid(Psid psid)
        {
            this.psid = psid;
            return this;
        }

        public Builder setSsp(ServiceSpecificPermissions ssp)
        {
            this.ssp = ssp;
            return this;
        }

        public PsidSsp createPsidSsp()
        {
            return new PsidSsp(psid, ssp);
        }
    }
}
