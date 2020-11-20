package org.bouncycastle.asn1.cms.ecc;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.OriginatorPublicKey;

/**
 * <a href="https://tools.ietf.org/html/rfc5753">RFC 5753/3278</a>: MQVuserKeyingMaterial object.
 * <pre>
 * MQVuserKeyingMaterial ::= SEQUENCE {
 *   ephemeralPublicKey OriginatorPublicKey,
 *   addedukm [0] EXPLICIT UserKeyingMaterial OPTIONAL  }
 * </pre>
 */
public class MQVuserKeyingMaterial
    extends ASN1Object
{
    private OriginatorPublicKey ephemeralPublicKey;
    private ASN1OctetString addedukm;

    public MQVuserKeyingMaterial(
        OriginatorPublicKey ephemeralPublicKey,
        ASN1OctetString addedukm)
    {
        if (ephemeralPublicKey == null)
        {
            throw new IllegalArgumentException("Ephemeral public key cannot be null");
        }

        this.ephemeralPublicKey = ephemeralPublicKey;
        this.addedukm = addedukm;
    }

    private MQVuserKeyingMaterial(
        ASN1Sequence seq)
    {
        if (seq.size() != 1 && seq.size() != 2)
        {
            throw new IllegalArgumentException("Sequence has incorrect number of elements");
        }

        this.ephemeralPublicKey = OriginatorPublicKey.getInstance(
            seq.getObjectAt(0));

        if (seq.size() > 1)
        {
            this.addedukm = ASN1OctetString.getInstance(
                (ASN1TaggedObject)seq.getObjectAt(1), true);
        }
    }

    /**
     * Return an MQVuserKeyingMaterial object from a tagged object.
     *
     * @param obj      the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *                 tagged false otherwise.
     * @throws IllegalArgumentException if the object held by the
     *                                  tagged object cannot be converted.
     */
    public static MQVuserKeyingMaterial getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    /**
     * Return an MQVuserKeyingMaterial object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link MQVuserKeyingMaterial} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence ASN1Sequence} with MQVuserKeyingMaterial inside it.
     * </ul>
     *
     * @param obj the object we want converted.
     * @throws IllegalArgumentException if the object cannot be converted.
     */
    public static MQVuserKeyingMaterial getInstance(
        Object obj)
    {
        if (obj instanceof MQVuserKeyingMaterial)
        {
            return (MQVuserKeyingMaterial)obj;
        }
        else if (obj != null)
        {
            return new MQVuserKeyingMaterial(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public OriginatorPublicKey getEphemeralPublicKey()
    {
        return ephemeralPublicKey;
    }

    public ASN1OctetString getAddedukm()
    {
        return addedukm;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(ephemeralPublicKey);

        if (addedukm != null)
        {
            v.add(new DERTaggedObject(true, 0, addedukm));
        }

        return new DERSequence(v);
    }
}
