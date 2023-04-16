package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.oer.its.ieee1609dot2.Opaque;

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
    private final ASN1Encodable serviceSpecificPermissions;

    public ServiceSpecificPermissions(int choice, ASN1Encodable object)
    {
        this.choice = choice;
        this.serviceSpecificPermissions = object;
    }

    private ServiceSpecificPermissions(ASN1TaggedObject sto)
    {
        this.choice = sto.getTagNo();
        switch (choice)
        {
        case opaque:
            serviceSpecificPermissions = Opaque.getInstance(sto.getExplicitBaseObject());
            return;
        case bitmapSsp:
            serviceSpecificPermissions = BitmapSsp.getInstance(sto.getExplicitBaseObject());
            return;
        }
        throw new IllegalArgumentException("invalid choice value " + choice);

    }


    public static ServiceSpecificPermissions getInstance(Object o)
    {
        if (o instanceof ServiceSpecificPermissions)
        {
            return (ServiceSpecificPermissions)o;
        }

        if (o != null)
        {
            return new ServiceSpecificPermissions(ASN1TaggedObject.getInstance(o, BERTags.CONTEXT_SPECIFIC));
        }

        return null;
    }

    public static ServiceSpecificPermissions opaque(ASN1OctetString octetString)
    {
        return new ServiceSpecificPermissions(opaque, octetString);
    }

    public static ServiceSpecificPermissions opaque(byte[] octetString)
    {
        return new ServiceSpecificPermissions(opaque, new DEROctetString(octetString));
    }


    public static ServiceSpecificPermissions bitmapSsp(BitmapSsp ssp)
    {
        return new ServiceSpecificPermissions(bitmapSsp, ssp);
    }


    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getServiceSpecificPermissions()
    {
        return serviceSpecificPermissions;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, serviceSpecificPermissions);
    }

}
