package org.bouncycastle.asn1.x9;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * ASN.1 def for Diffie-Hellman key exchange OtherInfo structure. See
 * RFC 2631, or X9.42, for further details.
 * <pre>
 *  OtherInfo ::= SEQUENCE {
 *      keyInfo KeySpecificInfo,
 *      partyAInfo [0] OCTET STRING OPTIONAL,
 *      suppPubInfo [2] OCTET STRING
 *  }
 * </pre>
 */
public class OtherInfo
    extends ASN1Object
{
    /**
     * Return a OtherInfo object from the passed in object.
     *
     * @param obj an object for conversion or a byte[].
     * @return a OtherInfo
     */
    public static OtherInfo getInstance(Object obj)
    {
        if (obj instanceof OtherInfo)
        {
            return (OtherInfo)obj;
        }
        else if (obj != null)
        {
            return new OtherInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static OtherInfo getInstance(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        return new OtherInfo(ASN1Sequence.getInstance(taggedObject, declaredExplicit));
    }

    public static OtherInfo getTagged(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        return new OtherInfo(ASN1Sequence.getTagged(taggedObject, declaredExplicit));
    }

    private final KeySpecificInfo keyInfo;
    private final ASN1OctetString partyAInfo;
    private final ASN1OctetString suppPubInfo;

    private OtherInfo(ASN1Sequence seq)
    {
        int count = seq.size(), pos = 0;
        if (count < 2 || count > 3)
        {
            throw new IllegalArgumentException("Bad sequence size: " + count);
        }

        this.keyInfo = KeySpecificInfo.getInstance(seq.getObjectAt(pos++));

        // partyAInfo [0] OCTET STRING OPTIONAL
        ASN1OctetString partyAInfo = null;
        if (pos < count)
        {
            ASN1TaggedObject tag0 = ASN1TaggedObject.getContextOptional(seq.getObjectAt(pos), 0);
            if (tag0 != null)
            {
                pos++;
                partyAInfo = ASN1OctetString.getTagged(tag0, true);
            }
        }
        this.partyAInfo = partyAInfo;

        ASN1TaggedObject tag2 = ASN1TaggedObject.getContextInstance(seq.getObjectAt(pos++), 2);        
        this.suppPubInfo = ASN1OctetString.getTagged(tag2, true);

        if (pos != count)
        {
            throw new IllegalArgumentException("Unexpected elements in sequence");
        }
    }

    public OtherInfo(KeySpecificInfo keyInfo, ASN1OctetString partyAInfo, ASN1OctetString suppPubInfo)
    {
        if (keyInfo == null)
        {
            throw new NullPointerException("'keyInfo' cannot be null");
        }
        if (suppPubInfo == null)
        {
            throw new NullPointerException("'suppPubInfo' cannot be null");
        }

        this.keyInfo = keyInfo;
        this.partyAInfo = partyAInfo;
        this.suppPubInfo = suppPubInfo;
    }

    /**
     * Return the key specific info for the KEK/CEK.
     *
     * @return the key specific info.
     */
    public KeySpecificInfo getKeyInfo()
    {
        return keyInfo;
    }

    /**
     * PartyA info for key deriviation.
     *
     * @return PartyA info.
     */
    public ASN1OctetString getPartyAInfo()
    {
        return partyAInfo;
    }

    /**
     * The length of the KEK to be generated as a 4 byte big endian.
     *
     * @return KEK length as a 4 byte big endian in an octet string.
     */
    public ASN1OctetString getSuppPubInfo()
    {
        return suppPubInfo;
    }

    /**
     * Return an ASN.1 primitive representation of this object.
     *
     * @return a DERSequence containing the OtherInfo values.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(keyInfo);

        if (partyAInfo != null)
        {
            v.add(new DERTaggedObject(0, partyAInfo));
        }

        v.add(new DERTaggedObject(2, suppPubInfo));

        return new DERSequence(v);
    }
}
