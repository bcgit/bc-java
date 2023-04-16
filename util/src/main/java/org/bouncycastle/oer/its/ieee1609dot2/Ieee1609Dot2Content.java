package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.Arrays;

/**
 * <pre>
 *     Ieee1609Dot2Content ::= CHOICE {
 *         unsecuredData Opaque,
 *         signedData SignedData,
 *         encryptedData EncryptedData,
 *         signedCertificateRequest Opaque,
 *         ...
 *     }
 * </pre>
 */
public class Ieee1609Dot2Content
    extends ASN1Object
    implements ASN1Choice
{
    public static final int unsecuredData = 0;
    public static final int signedData = 1;
    public static final int encryptedData = 2;
    public static final int signedCertificateRequest = 3;


    private final int choice;
    private final ASN1Encodable ieee1609Dot2Content;

    public Ieee1609Dot2Content(int choice, ASN1Encodable object)
    {
        this.choice = choice;
        this.ieee1609Dot2Content = object;
    }


    public static Ieee1609Dot2Content unsecuredData(Opaque value)
    {
        return new Ieee1609Dot2Content(unsecuredData, value);
    }

    public static Ieee1609Dot2Content unsecuredData(byte[] value)
    {
        return new Ieee1609Dot2Content(unsecuredData, new DEROctetString(Arrays.clone(value)));
    }

    public static Ieee1609Dot2Content signedData(SignedData value)
    {
        return new Ieee1609Dot2Content(signedData, value);
    }

    public static Ieee1609Dot2Content encryptedData(EncryptedData value)
    {
        return new Ieee1609Dot2Content(encryptedData, value);
    }

    public static Ieee1609Dot2Content signedCertificateRequest(Opaque value)
    {
        return new Ieee1609Dot2Content(signedCertificateRequest, value);
    }

    public static Ieee1609Dot2Content signedCertificateRequest(byte[] value)
    {
        return new Ieee1609Dot2Content(signedCertificateRequest, new DEROctetString(Arrays.clone(value)));
    }



    private Ieee1609Dot2Content(ASN1TaggedObject to)
    {
        choice = to.getTagNo();
        switch (choice)
        {
        case unsecuredData:
        case signedCertificateRequest:
            ieee1609Dot2Content = Opaque.getInstance(to.getExplicitBaseObject());
            return;
        case signedData:
            ieee1609Dot2Content = SignedData.getInstance(to.getExplicitBaseObject());
            return;
        case encryptedData:
            ieee1609Dot2Content = EncryptedData.getInstance(to.getExplicitBaseObject());
            return;
        default:
            throw new IllegalArgumentException("invalid choice value " + to.getTagNo());
        }
    }


    public static Ieee1609Dot2Content getInstance(Object src)
    {
        if (src instanceof Ieee1609Dot2Content)
        {
            return (Ieee1609Dot2Content)src;
        }

        if (src != null)
        {
            return new Ieee1609Dot2Content(ASN1TaggedObject.getInstance(src, BERTags.CONTEXT_SPECIFIC));
        }
        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, ieee1609Dot2Content);
    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getIeee1609Dot2Content()
    {
        return ieee1609Dot2Content;
    }

}
