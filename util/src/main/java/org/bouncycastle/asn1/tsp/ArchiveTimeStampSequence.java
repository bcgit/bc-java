package org.bouncycastle.asn1.tsp;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * Implementation of ArchiveTimeStampSequence type, as defined in RFC4998.
 * <p>
 * An ArchiveTimeStampSequence corresponds to a SEQUENCE OF ArchiveTimeStampChains and has the
 * following ASN.1 Syntax:
 * <p>
 * ArchiveTimeStampSequence ::= SEQUENCE OF ArchiveTimeStampChain
 */
public class ArchiveTimeStampSequence
    extends ASN1Object
{
    private ASN1Sequence archiveTimeStampChains;

    /**
     * Return an ArchiveTimestampSequence from the given object.
     *
     * @param obj the object we want converted.
     * @return an ArchiveTimeStampSequence instance, or null.
     * @throws IllegalArgumentException if the object cannot be converted.
     */
    public static ArchiveTimeStampSequence getInstance(final Object obj)
    {
        if (obj instanceof ArchiveTimeStampChain)
        {
            return (ArchiveTimeStampSequence)obj;
        }
        else if (obj != null)
        {
            return new ArchiveTimeStampSequence(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private ArchiveTimeStampSequence(final ASN1Sequence sequence)
        throws IllegalArgumentException
    {
        final ASN1EncodableVector vector = new ASN1EncodableVector(sequence.size());

        Enumeration objects = sequence.getObjects();
        while (objects.hasMoreElements())
        {
            vector.add(ArchiveTimeStampChain.getInstance(objects.nextElement()));
        }

        this.archiveTimeStampChains = new DERSequence(vector);
    }

    public ArchiveTimeStampSequence(ArchiveTimeStampChain archiveTimeStampChain)
    {
        this.archiveTimeStampChains = new DERSequence(archiveTimeStampChain);
    }

    public ArchiveTimeStampSequence(ArchiveTimeStampChain[] archiveTimeStampChains)
    {
        this.archiveTimeStampChains = new DERSequence(archiveTimeStampChains);
    }

    /**
     * Returns the sequence of ArchiveTimeStamp chains that compose the ArchiveTimeStamp sequence.
     *
     * @return the {@link ASN1Sequence} containing the ArchiveTimeStamp chains.
     */
    public ArchiveTimeStampChain[] getArchiveTimeStampChains()
    {
        ArchiveTimeStampChain[] rv = new ArchiveTimeStampChain[archiveTimeStampChains.size()];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = ArchiveTimeStampChain.getInstance(archiveTimeStampChains.getObjectAt(i));
        }

        return rv;
    }

    public int size()
    {
        return archiveTimeStampChains.size();
    }

    /**
     * Adds an {@link ArchiveTimeStampChain} to the ArchiveTimeStamp sequence.
     *
     * @param chain the {@link ArchiveTimeStampChain} to add
     * @return returns the modified sequence.
     */
    public ArchiveTimeStampSequence append(ArchiveTimeStampChain chain) {

        ASN1EncodableVector v = new ASN1EncodableVector(archiveTimeStampChains.size() + 1);

        for (int i = 0; i != archiveTimeStampChains.size(); i++)
        {
            v.add(archiveTimeStampChains.getObjectAt(i));
        }

        v.add(chain);

        return new ArchiveTimeStampSequence(new DERSequence(v));
    }

    public ASN1Primitive toASN1Primitive()
    {
        return archiveTimeStampChains;
    }
}
