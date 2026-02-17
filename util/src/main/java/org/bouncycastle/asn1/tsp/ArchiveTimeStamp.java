package org.bouncycastle.asn1.tsp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Implementation of the Archive Timestamp type defined in RFC4998.
 * @see <a href="https://tools.ietf.org/html/rfc4998">RFC 4998</a>
 * <p>
 * ASN.1 Archive Timestamp
 * <p>
 * ArchiveTimeStamp ::= SEQUENCE {
 * digestAlgorithm [Ø] AlgorithmIdentifier OPTIONAL,
 * attributes      [1] Attributes OPTIONAL,
 * reducedHashtree [2] SEQUENCE OF PartialHashtree OPTIONAL,
 * timeStamp       ContentInfo}
 * <p>
 * PartialHashtree ::= SEQUENCE OF OCTET STRING
 * <p>
 * Attributes ::= SET SIZE (1..MAX) OF Attribute
 */
public class ArchiveTimeStamp
    extends ASN1Object
{
    /**
     * Return an ArchiveTimestamp from the given object.
     *
     * @param obj the object we want converted.
     * @return an ArchiveTimestamp instance, or null.
     * @throws IllegalArgumentException if the object cannot be converted.
     */
    public static ArchiveTimeStamp getInstance(Object obj)
    {
        if (obj instanceof ArchiveTimeStamp)
        {
            return (ArchiveTimeStamp)obj;
        }
        else if (obj != null)
        {
            return new ArchiveTimeStamp(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static ArchiveTimeStamp getInstance(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        return new ArchiveTimeStamp(ASN1Sequence.getInstance(taggedObject, declaredExplicit));
    }

    public static ArchiveTimeStamp getTagged(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        return new ArchiveTimeStamp(ASN1Sequence.getTagged(taggedObject, declaredExplicit));
    }

    private final AlgorithmIdentifier digestAlgorithm;
    private final Attributes attributes;
    private final ASN1Sequence reducedHashTree;
    private final ContentInfo timeStamp;

    public ArchiveTimeStamp(
        AlgorithmIdentifier digestAlgorithm,
        PartialHashtree[] reducedHashTree,
        ContentInfo timeStamp)
    {
        this(digestAlgorithm, null, reducedHashTree, timeStamp);
    }

    public ArchiveTimeStamp(
        ContentInfo timeStamp)
    {
        this(null, null, null, timeStamp);
    }

    public ArchiveTimeStamp(
        AlgorithmIdentifier digestAlgorithm,
        Attributes attributes,
        PartialHashtree[] reducedHashTree,
        ContentInfo timeStamp)
    {
        if (timeStamp == null)
        {
            throw new NullPointerException("'timeStamp' cannot be null");
        }

        this.digestAlgorithm = digestAlgorithm;
        this.attributes = attributes;
        this.reducedHashTree = DERSequence.fromElementsOptional(reducedHashTree);
        this.timeStamp = timeStamp;
    }

    private ArchiveTimeStamp(ASN1Sequence seq)
    {
        int count = seq.size(), pos = 0;
        if (count < 1 || count > 4)
        {
            throw new IllegalArgumentException("Bad sequence size: " + count);
        }

        // digestAlgorithm [Ø] AlgorithmIdentifier OPTIONAL
        AlgorithmIdentifier digestAlgorithm = null;
        if (pos < count)
        {
            ASN1TaggedObject tag0 = ASN1TaggedObject.getContextOptional(seq.getObjectAt(pos), 0);
            if (tag0 != null)
            {
                pos++;
                digestAlgorithm = AlgorithmIdentifier.getTagged(tag0, false);
            }
        }
        this.digestAlgorithm = digestAlgorithm;

        // attributes [1] Attributes OPTIONAL
        Attributes attributes = null;
        if (pos < count)
        {
            ASN1TaggedObject tag1 = ASN1TaggedObject.getContextOptional(seq.getObjectAt(pos), 1);
            if (tag1 != null)
            {
                pos++;
                attributes = Attributes.getTagged(tag1, false);
            }
        }
        this.attributes = attributes;

        // reducedHashtree [2] SEQUENCE OF PartialHashtree OPTIONAL
        ASN1Sequence reducedHashTree = null;
        if (pos < count)
        {
            ASN1TaggedObject tag2 = ASN1TaggedObject.getContextOptional(seq.getObjectAt(pos), 2);
            if (tag2 != null)
            {
                pos++;
                reducedHashTree = ASN1Sequence.getInstance(tag2, false);
            }
        }
        this.reducedHashTree = reducedHashTree;

        // timeStamp ContentInfo
        timeStamp = ContentInfo.getInstance(seq.getObjectAt(pos++));

        if (pos != count)
        {
            throw new IllegalArgumentException("Unexpected elements in sequence");
        }
    }

    public AlgorithmIdentifier getDigestAlgorithmIdentifier()
    {
        if (digestAlgorithm != null)
        {
            return digestAlgorithm;
        }

        return getTimeStampInfo().getMessageImprint().getHashAlgorithm();
    }

    public byte[] getTimeStampDigestValue()
    {
        return getTimeStampInfo().getMessageImprint().getHashedMessage();
    }

    private TSTInfo getTimeStampInfo()
    {
        if (!CMSObjectIdentifiers.signedData.equals(timeStamp.getContentType()))
        {
            throw new IllegalStateException("cannot identify algorithm identifier for digest");
        }

        SignedData tsData = SignedData.getInstance(timeStamp.getContent());
        ContentInfo encapContentInfo = tsData.getEncapContentInfo();

        if (!PKCSObjectIdentifiers.id_ct_TSTInfo.equals(encapContentInfo.getContentType()))
        {
            throw new IllegalStateException("cannot parse time stamp");
        }

        ASN1OctetString encapContent = ASN1OctetString.getInstance(encapContentInfo.getContent());

        return TSTInfo.getInstance(encapContent.getOctets());
    }

    /**
     * Return the contents of the digestAlgorithm field - null if not set.
     *
     * @return the contents of the digestAlgorithm field, or null if not set.
     */
    public AlgorithmIdentifier getDigestAlgorithm()
    {
        return digestAlgorithm;
    }

    /**
     * Return the first node in the reduced hash tree which contains the leaf node.
     *
     * @return the node containing the data hashes, null if no reduced hash tree is present.
     */
    public PartialHashtree getHashTreeLeaf()
    {
        if (reducedHashTree == null)
        {
            return null;
        }

        return PartialHashtree.getInstance(reducedHashTree.getObjectAt(0));
    }

    public PartialHashtree[] getReducedHashTree()
    {
        if (reducedHashTree == null)
        {
           return null;
        }

        PartialHashtree[] rv = new PartialHashtree[reducedHashTree.size()];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = PartialHashtree.getInstance(reducedHashTree.getObjectAt(i));
        }

        return rv;
    }

    public ContentInfo getTimeStamp()
    {
        return timeStamp;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(4);

        if (digestAlgorithm != null)
        {
            v.add(new DERTaggedObject(false, 0, digestAlgorithm));
        }

        if (attributes != null)
        {
            v.add(new DERTaggedObject(false, 1, attributes));
        }

        if (reducedHashTree != null)
        {
            v.add(new DERTaggedObject(false, 2, reducedHashTree));
        }

        v.add(timeStamp);

        return new DERSequence(v);
    }
}
