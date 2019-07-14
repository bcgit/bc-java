package org.bouncycastle.asn1.bc;

import java.math.BigInteger;
import java.util.Date;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * <pre>
 * ObjectStoreData ::= SEQUENCE {
 *     version INTEGER.
 *     dataSalt OCTET STRING,
 *     integrityAlgorithm AlgorithmIdentifier,
 *     creationDate GeneralizedTime,
 *     lastModifiedDate GeneralizedTime,
 *     objectDataSequence ObjectDataSequence,
 *     comment UTF8String OPTIONAL
 * }
 * </pre>
 */
public class ObjectStoreData
    extends ASN1Object
{
    private final BigInteger version;
    private final AlgorithmIdentifier integrityAlgorithm;
    private final ASN1GeneralizedTime creationDate;
    private final ASN1GeneralizedTime lastModifiedDate;
    private final ObjectDataSequence objectDataSequence;
    private final String comment;

    public ObjectStoreData(AlgorithmIdentifier integrityAlgorithm, Date creationDate, Date lastModifiedDate, ObjectDataSequence objectDataSequence, String comment)
    {
        this.version = BigInteger.valueOf(1);
        this.integrityAlgorithm = integrityAlgorithm;
        this.creationDate = new DERGeneralizedTime(creationDate);
        this.lastModifiedDate = new DERGeneralizedTime(lastModifiedDate);
        this.objectDataSequence = objectDataSequence;
        this.comment = comment;
    }

    private ObjectStoreData(ASN1Sequence seq)
    {
        this.version = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
        this.integrityAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        this.creationDate = ASN1GeneralizedTime.getInstance(seq.getObjectAt(2));
        this.lastModifiedDate = ASN1GeneralizedTime.getInstance(seq.getObjectAt(3));
        this.objectDataSequence = ObjectDataSequence.getInstance(seq.getObjectAt(4));
        this.comment = (seq.size() == 6) ? DERUTF8String.getInstance(seq.getObjectAt(5)).getString() : null;
    }

    public static ObjectStoreData getInstance(Object o)
    {
        if (o instanceof ObjectStoreData)
        {
            return (ObjectStoreData)o;
        }
        else if (o != null)
        {
            return new ObjectStoreData(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public String getComment()
    {
        return comment;
    }

    public ASN1GeneralizedTime getCreationDate()
    {
        return creationDate;
    }

    public AlgorithmIdentifier getIntegrityAlgorithm()
    {
        return integrityAlgorithm;
    }

    public ASN1GeneralizedTime getLastModifiedDate()
    {
        return lastModifiedDate;
    }

    public ObjectDataSequence getObjectDataSequence()
    {
        return objectDataSequence;
    }

    public BigInteger getVersion()
    {
        return version;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(6);

        v.add(new ASN1Integer(version));
        v.add(integrityAlgorithm);
        v.add(creationDate);
        v.add(lastModifiedDate);
        v.add(objectDataSequence);

        if (comment != null)
        {
            v.add(new DERUTF8String(comment));
        }

        return new DERSequence(v);
    }
}
