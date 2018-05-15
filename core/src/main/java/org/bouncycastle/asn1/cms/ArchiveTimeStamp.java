package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.util.Enumeration;

/**
 * Implementation of the Archive Timestamp type defined in RFC4998.
 * {@see <a href="https://tools.ietf.org/html/rfc4998">RFC 4998</a>}
 *
 * ASN.1 Archive Timestamp
 *
 * ArchiveTimeStamp ::= SEQUENCE {
 *   digestAlgorithm [Ø] AlgorithmIdentifier OPTIONAL,
 *   attributes      [1] Attributes OPTIONAL,
 *   reducedHashtree [2] SEQUENCE OF PartialHashtree OPTIONAL,
 *   timeStamp       ContentInfo}
 *
 * PartialHashtree ::= SEQUENCE OF OCTET STRING
 *
 * Attributes ::= SET SIZE (1..MAX) OF Attribute
 */
public class ArchiveTimeStamp
    extends ASN1Object
{
    private ASN1TaggedObject digestAlgorithm;
    private ASN1TaggedObject attributes;
    private ASN1TaggedObject reducedHashTree;
    private ContentInfo timeStamp;

    /**
     * Return an ArchiveTimestamp from the given object.
     *
     * @param obj the object we want converted.
     *
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ArchiveTimestamp instance, or null.
     */
    public static ArchiveTimeStamp getInstance(final Object obj)
    {
        if (obj == null || obj instanceof ArchiveTimeStamp)
        {
            return (ArchiveTimeStamp) obj;
        }
        else if (obj instanceof ContentInfo)
        {
            return new ArchiveTimeStamp(ContentInfo.getInstance(obj));
        }
        else if (obj instanceof ASN1Sequence || obj instanceof byte[])
        {
            return new ArchiveTimeStamp(ASN1Sequence.getInstance(obj));
        }

        throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName());
    }

    //todo: remove ?
    protected ArchiveTimeStamp (
        final AlgorithmIdentifier digestAlgorithm,
        final ASN1TaggedObject reducedHashTree,
        final ContentInfo timeStamp)
    {
        this.digestAlgorithm = new DERTaggedObject(false, 0, digestAlgorithm);
        this.reducedHashTree = reducedHashTree;
        this.timeStamp = timeStamp;
    }

    private ArchiveTimeStamp (
        final ContentInfo timeStamp)
    {
        this.timeStamp = timeStamp;
    }

    private ArchiveTimeStamp(final ASN1Sequence sequence)
    {
        if (sequence.size() < 1 || sequence.size() > 4)
        {
            throw new IllegalArgumentException("wrong sequence size in constructor: " + sequence
                .size());
        }

        Enumeration objects = sequence.getObjects();

        while (objects.hasMoreElements())
        {
            final Object obj = objects.nextElement();

            if (obj instanceof ASN1TaggedObject)
            {
                final ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(obj);
                final Object object = taggedObject.getObject();

                switch (taggedObject.getTagNo()) {
                    case 0:
                        if (object instanceof AlgorithmIdentifier || object instanceof ASN1Sequence)
                        {
                            AlgorithmIdentifier.getInstance(object);
                            digestAlgorithm = taggedObject;
                        }
                        else if (object instanceof ASN1ObjectIdentifier)
                        {
                            final AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(
                                new DERSequence((ASN1ObjectIdentifier) object));
                            digestAlgorithm = new DERTaggedObject(false, 0,
                                algId);
                        }
                        else
                        {
                            throw new IllegalArgumentException("unknown object in constructor: "
                                + object.getClass().getName());
                        }
                        break;
                    case 1:
                        if (object instanceof Attributes)
                        {
                            attributes = taggedObject;
                            break;
                        }
                        else
                        {
                            throw new IllegalArgumentException("unknown object in constructor: "
                                + object.getClass().getName());
                        }
                    case 2:
                        if (object instanceof ASN1Sequence)
                        {
                            ASN1Sequence rhtSequence = ASN1Sequence.getInstance(object);
                            ASN1EncodableVector vector = new ASN1EncodableVector();
                            Enumeration enumeration = rhtSequence.getObjects();

                            Object o = enumeration.nextElement();
                            if (o instanceof DEROctetString)
                            {
                                vector.add(DEROctetString.getInstance(o));
                                while (enumeration.hasMoreElements())
                                {
                                    vector.add(DEROctetString.getInstance(
                                        enumeration.nextElement()));
                                }
                                final PartialHashtree pht = PartialHashtree.getInstance(vector);
                                reducedHashTree = new DERTaggedObject(false, 2, new DERSequence
                                    (pht));
                            }
                            else
                            {
                                vector.add(PartialHashtree.getInstance(o));
                                while (enumeration.hasMoreElements())
                                {
                                    vector.add(PartialHashtree.getInstance(enumeration.nextElement()));
                                }
                                reducedHashTree = new DERTaggedObject(false, 2, new DERSequence
                                    (vector));
                            }
                            break;
                        }
                        else
                        {
                            throw new IllegalArgumentException("unknown object in constructor: "
                                + object.getClass().getName());
                        }
                    default: throw new IllegalArgumentException("invalid tag no in constructor: "
                        + taggedObject.getTagNo());
                }
            }
            else if (obj instanceof ASN1Sequence)
            {
                timeStamp = ContentInfo.getInstance(obj);
            }
            else if (! (obj instanceof DERNull))
            {
                throw new IllegalArgumentException("unknown object in constructor: " + obj
                    .getClass().getName());
            }
        }
    }

    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        if (digestAlgorithm != null)
        {
            return AlgorithmIdentifier.getInstance(digestAlgorithm.getObject());
        }
        else
        {
            final ASN1Sequence tstSequence = DERSequence.getInstance(timeStamp.getContent());
            Enumeration objects = tstSequence.getObjects();
            while (objects.hasMoreElements()) {
                final Object object = objects.nextElement();

                if (object instanceof ASN1Sequence) {
                    try {
                        ASN1TaggedObject taggedObject = DERTaggedObject.getInstance((
                            (ASN1Sequence) object)
                            .getObjectAt(1));
                        ASN1OctetString octetString = DEROctetString
                            .getInstance(taggedObject.getObject());
                        TSTInfo instance = TSTInfo.getInstance(octetString.getOctets());
                        return instance.getMessageImprint().getHashAlgorithm();
                    } catch (IllegalArgumentException e) {}
                }
            }
            return null;
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (digestAlgorithm != null)
        {
            v.add(digestAlgorithm);
        }

        if (attributes != null)
        {
            v.add(attributes);
        }

        if (reducedHashTree != null)
        {
            v.add(reducedHashTree);
        }

        v.add(timeStamp);

        return new DERSequence(v);
    }

    public ContentInfo getTimeStamp () {
        return timeStamp;
    }

    public ASN1TaggedObject getReducedHashTree ()
    {
        return reducedHashTree;
    }

}