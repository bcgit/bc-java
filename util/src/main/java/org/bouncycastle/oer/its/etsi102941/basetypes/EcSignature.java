package org.bouncycastle.oer.its.etsi102941.basetypes;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataEncrypted;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataSignedExternalPayload;

/**
 * EcSignature::= CHOICE {
 * encryptedEcSignature EtsiTs103097Data-Encrypted{EtsiTs103097Data-SignedExternalPayload},
 * ecSignature EtsiTs103097Data-SignedExternalPayload
 * }
 */
public class EcSignature
    extends ASN1Object
    implements ASN1Choice
{

    public static final int encryptedEcSignature = 0;
    public static final int ecSignature = 1;


    private final int choice;
    private final ASN1Encodable _ecSignature;

    public EcSignature(int choice, ASN1Encodable ecSignature)
    {
        this.choice = choice;
        this._ecSignature = ecSignature;
    }

    private EcSignature(ASN1TaggedObject ato)
    {
        choice = ato.getTagNo();

        switch (choice)
        {
        case encryptedEcSignature:
            _ecSignature = EtsiTs103097DataEncrypted.getInstance(ato.getExplicitBaseObject());
            return;
        case ecSignature:
            _ecSignature = EtsiTs103097DataSignedExternalPayload.getInstance(ato.getExplicitBaseObject());
            return;
        }

        throw new IllegalArgumentException("invalid choice value " + choice);
    }

    public static EcSignature getInstance(Object o)
    {
        if (o instanceof EcSignature)
        {
            return (EcSignature)o;
        }
        if (o != null)
        {
            return new EcSignature(ASN1TaggedObject.getInstance(o, BERTags.CONTEXT_SPECIFIC));
        }

        return null;
    }


    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getEcSignature()
    {
        return _ecSignature;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, _ecSignature);
    }
}
