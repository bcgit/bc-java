package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.*;

import java.util.Enumeration;

/**
 * Implementation of ArchiveTimeStampSequence type, as defined in RFC4998.
 *
 * An ArchiveTimeStampSequence corresponds to a SEQUENCE OF ArchiveTimeStampChains and has the
 * following ASN.1 Syntax:
 *
 * ArchiveTimeStampSequence ::= SEQUENCE OF ArchiveTimeStampChain
 */
public class ArchiveTimeStampSequence extends ASN1Object
{

    private ASN1Sequence archiveTimeStampChains;

    /**
     * Return an ArchiveTimestampSequence from the given object.
     *
     * @param obj the object we want converted.
     *
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ArchiveTimeStampSequence instance, or null.
     */
    public static ArchiveTimeStampSequence getInstance(final Object obj)
    {
        if (obj == null || obj instanceof ArchiveTimeStampSequence)
        {
            return (ArchiveTimeStampSequence) obj;
        }
        else if (obj instanceof ArchiveTimeStampChain)
        {
            return new ArchiveTimeStampSequence(ArchiveTimeStampChain.getInstance(obj));
        }
        else if (obj instanceof ASN1Sequence || obj instanceof byte[])
        {
            return new ArchiveTimeStampSequence(ASN1Sequence.getInstance(obj));
        }

        throw new IllegalArgumentException("unknown object in getInstance");
    }

    private ArchiveTimeStampSequence(final ASN1Sequence sequence)
        throws IllegalArgumentException
    {
        final ASN1EncodableVector vector = new ASN1EncodableVector();
        Enumeration objects = sequence.getObjects();

        while (objects.hasMoreElements())
        {
            vector.add(ArchiveTimeStampChain.getInstance(objects.nextElement()));
        }

        archiveTimeStampChains = new DERSequence(vector);
    }

    private ArchiveTimeStampSequence(final ArchiveTimeStampChain archiveTimeStampChain)
    {
        final ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(archiveTimeStampChain);
        archiveTimeStampChains = new DERSequence(vector);
    }

    /**
     * Returns the sequence of ArchiveTimeStamp chains that compose the ArchiveTimeStamp sequence.
     *
     * @return the {@link ASN1Sequence} containing the ArchiveTimeStamp chains.
     */
    public ASN1Sequence getArchiveTimeStampChains ()
    {
        return archiveTimeStampChains;
    }

    /**
     * Adds an {@link ArchiveTimeStampChain} to the ArchiveTimeStamp sequence.
     *
     * @param chain the {@link ArchiveTimeStampChain} to add
     */
    protected void add(ArchiveTimeStampChain chain) {

        final ASN1EncodableVector vector = new ASN1EncodableVector();

        for (int i = 0; i != archiveTimeStampChains.size(); i++)
        {
            vector.add(archiveTimeStampChains.getObjectAt(i));
        }

        vector.add(chain);

        archiveTimeStampChains = new DERSequence(vector);
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        final ASN1EncodableVector vector = new ASN1EncodableVector();

        for (final ASN1Encodable chain : archiveTimeStampChains)
        {
            vector.add(chain);
        }

        return new DERSequence(vector);
    }
}
