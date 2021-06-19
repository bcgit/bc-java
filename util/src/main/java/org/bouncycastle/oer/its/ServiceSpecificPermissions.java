package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
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
    public static final int bitmapSsp = 1;

    private final int choice;
    private final ASN1Encodable object;

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
        case bitmapSsp:
            return new Builder()
                .setChoice(dto.getTagNo())
                .setObject(dto.getObject())
                .createServiceSpecificPermissions();
        default:
            throw new IllegalArgumentException("unknown choice " + dto.getTagNo());
        }
    }


    public ServiceSpecificPermissions(int choice, ASN1Encodable object)
    {
        this.choice = choice;
        this.object = object;
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

        public ServiceSpecificPermissions createServiceSpecificPermissions()
        {
            return new ServiceSpecificPermissions(choice, object);
        }
    }
}
