package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.*;

import java.util.Enumeration;

/**
 * Implementation of ArchiveTimeStampChain type, as defined in RFC4998 and RFC6283.
 *
 * An ArchiveTimeStampChain corresponds to a SEQUENCE OF ArchiveTimeStamps, and has the following
 * ASN.1 Syntax:
 *
 * ArchiveTimeStampChain ::= SEQUENCE OF ArchiveTimeStamp
 */
public class ArchiveTimeStampChain extends ASN1Object
{

    public ASN1Sequence getArchiveTimestamps() {
        return archiveTimestamps;
    }

    private ASN1Sequence archiveTimestamps;

    /**
     * Return an ArchiveTimeStampChain from the given object.
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ArchiveTimeStampChain instance, or null.
     */
    public static ArchiveTimeStampChain getInstance (final Object obj)
    {
        if (obj == null || obj instanceof ArchiveTimeStampChain)
        {
            return (ArchiveTimeStampChain) obj;
        }
        else if (obj instanceof ArchiveTimeStamp)
        {
            return new ArchiveTimeStampChain((ArchiveTimeStamp) obj);
        }
        else if (obj instanceof ASN1Sequence || obj instanceof byte[])
        {
            return new ArchiveTimeStampChain(ASN1Sequence.getInstance(obj));
        }
        else if (obj instanceof ASN1Encodable)
        {
            ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();

            if (primitive instanceof ASN1Sequence)
            {
                return new ArchiveTimeStampChain((ASN1Sequence) primitive);
            }
        }

        throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName());
    }

    private ArchiveTimeStampChain (final ASN1Sequence sequence)
    {
        final ASN1EncodableVector vector = new ASN1EncodableVector();
        final Enumeration objects = sequence.getObjects();

        while (objects.hasMoreElements())
        {
            vector.add(ArchiveTimeStamp.getInstance(objects.nextElement()));
        }

        archiveTimestamps = new DERSequence(vector);
    }

    private ArchiveTimeStampChain (final ArchiveTimeStamp archiveTimeStamp)
    {
        final ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(archiveTimeStamp);

        this.archiveTimestamps = new DERSequence(v);
    }

    /**
     * Adds an {@link ArchiveTimeStamp} object to the archive timestamp chain.
     * @param archiveTimeStamp the {@link ArchiveTimeStamp} to add.
     */
    protected void add(final ArchiveTimeStamp archiveTimeStamp)
    {
        final ASN1EncodableVector vector = new ASN1EncodableVector();
        for (final ASN1Encodable ats : archiveTimestamps)
        {
            vector.add(ats);
        }

        vector.add(archiveTimeStamp);

        this.archiveTimestamps = new DERSequence(vector);
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return archiveTimestamps;
    }
}
