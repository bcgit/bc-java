package org.bouncycastle.asn1.x9;

import java.util.Enumeration;

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
    private KeySpecificInfo     keyInfo;
    private ASN1OctetString     partyAInfo;
    private ASN1OctetString     suppPubInfo;

    public OtherInfo(
        KeySpecificInfo     keyInfo,
        ASN1OctetString     partyAInfo,
        ASN1OctetString     suppPubInfo)
    {
        this.keyInfo = keyInfo;
        this.partyAInfo = partyAInfo;
        this.suppPubInfo = suppPubInfo;
    }

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

    private OtherInfo(
        ASN1Sequence  seq)
    {
        Enumeration e = seq.getObjects();

        keyInfo = KeySpecificInfo.getInstance(e.nextElement());

        while (e.hasMoreElements())
        {
            ASN1TaggedObject o = (ASN1TaggedObject)e.nextElement();

            if (o.getTagNo() == 0)
            {
                partyAInfo = (ASN1OctetString)o.getObject();
            }
            else if (o.getTagNo() == 2)
            {
                suppPubInfo = (ASN1OctetString)o.getObject();
            }
        }
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
