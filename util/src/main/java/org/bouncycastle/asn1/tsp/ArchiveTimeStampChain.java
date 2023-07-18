package org.bouncycastle.asn1.tsp;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * Implementation of ArchiveTimeStampChain type, as defined in RFC4998 and RFC6283.
 * <p>
 * An ArchiveTimeStampChain corresponds to a SEQUENCE OF ArchiveTimeStamps, and has the following
 * ASN.1 Syntax:
 * <p>
 * ArchiveTimeStampChain ::= SEQUENCE OF ArchiveTimeStamp
 */
public class ArchiveTimeStampChain
    extends ASN1Object
{
    private ASN1Sequence archiveTimeStamps;

    /**
     * Return an ArchiveTimeStampChain from the given object.
     *
     * @param obj the object we want converted.
     * @return an ArchiveTimeStampChain instance, or null.
     * @throws IllegalArgumentException if the object cannot be converted.
     */
    public static ArchiveTimeStampChain getInstance(final Object obj)
    {
        if (obj instanceof ArchiveTimeStampChain)
        {
            return (ArchiveTimeStampChain)obj;
        }
        else if (obj != null)
        {
            return new ArchiveTimeStampChain(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public ArchiveTimeStampChain(ArchiveTimeStamp archiveTimeStamp)
    {
        this.archiveTimeStamps = new DERSequence(archiveTimeStamp);
    }

    public ArchiveTimeStampChain(ArchiveTimeStamp[] archiveTimeStamps)
    {
        this.archiveTimeStamps = new DERSequence(archiveTimeStamps);
    }

    private ArchiveTimeStampChain(final ASN1Sequence sequence)
    {
        final ASN1EncodableVector vector = new ASN1EncodableVector(sequence.size());

        final Enumeration objects = sequence.getObjects();
        while (objects.hasMoreElements())
        {
            vector.add(ArchiveTimeStamp.getInstance(objects.nextElement()));
        }

        this.archiveTimeStamps = new DERSequence(vector);
    }

    public ArchiveTimeStamp[] getArchiveTimestamps()
    {
        ArchiveTimeStamp[] rv = new ArchiveTimeStamp[archiveTimeStamps.size()];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = ArchiveTimeStamp.getInstance(archiveTimeStamps.getObjectAt(i));
        }

        return rv;
    }

    /**
     * Adds an {@link ArchiveTimeStamp} object to the archive timestamp chain.
     *
     * @param archiveTimeStamp the {@link ArchiveTimeStamp} to add.
     * @return returns the modified chain.
     */
    public ArchiveTimeStampChain append(final ArchiveTimeStamp archiveTimeStamp)
    {
        ASN1EncodableVector v = new ASN1EncodableVector(archiveTimeStamps.size() + 1);

        for (int i = 0; i != archiveTimeStamps.size(); i++)
        {
            v.add(archiveTimeStamps.getObjectAt(i));
        }

        v.add(archiveTimeStamp);

        return new ArchiveTimeStampChain(new DERSequence(v));
    }

    public ASN1Primitive toASN1Primitive()
    {
        return archiveTimeStamps;
    }
}
