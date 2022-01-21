package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * ServiceSpecificPermissions ::= CHOICE {
 * opaque     OCTET STRING (SIZE(0..MAX)),
 * ...,
 * bitmapSsp  BitmapSsp
 * }
 */
public class ServiceSpecificPermissions
    extends ASN1Object
    implements ASN1Choice
{

    public static final int opaque = 0;
    public static final int extension = 1;
    public static final int bitmapSsp = 2;

    private final int choice;
    private final ASN1Encodable object;

    public ServiceSpecificPermissions(int choice, ASN1Encodable object)
    {
        this.choice = choice;
        this.object = object;
    }

    public static ServiceSpecificPermissions getInstance(Object o)
    {
        if (o instanceof ServiceSpecificPermissions)
        {
            return (ServiceSpecificPermissions)o;
        }
        ASN1TaggedObject dto = ASN1TaggedObject.getInstance(o);
        switch (dto.getTagNo())
        {
        case opaque:
        case extension:
            return new ServiceSpecificPermissions(dto.getTagNo(), DEROctetString.getInstance(dto.getObject()));
        case bitmapSsp:
            return new ServiceSpecificPermissions(dto.getTagNo(), BitmapSsp.getInstance(dto.getObject()));
        default:
            throw new IllegalArgumentException("unknown choice " + dto.getTagNo());
        }
    }

    public static Builder builder()
    {
        return new ServiceSpecificPermissions.Builder();
    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getObject()
    {
        return object;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, object);
    }

    public static class Builder
    {
        private int choice;
        private ASN1Encodable object;

        public Builder setChoice(int choice)
        {
            this.choice = choice;
            return this;
        }

        public Builder setObject(ASN1Encodable object)
        {
            this.object = object;
            return this;
        }

        public Builder opaque()
        {
            return setChoice(ServiceSpecificPermissions.opaque);
        }

        public Builder extension(byte[] data)
        {
            return setChoice(ServiceSpecificPermissions.bitmapSsp).setObject(new DEROctetString(data));
        }

        public Builder bitmapSsp(ASN1OctetString octetString)
        {
            return setChoice(ServiceSpecificPermissions.bitmapSsp).setObject(octetString);
        }

        public ServiceSpecificPermissions createServiceSpecificPermissions()
        {
            return new ServiceSpecificPermissions(choice, object);
        }
    }
}
