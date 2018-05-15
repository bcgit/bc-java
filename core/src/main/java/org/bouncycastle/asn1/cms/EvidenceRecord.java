package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.math.BigInteger;
import java.util.Enumeration;

/**
 * <a href="https://tools.ietf.org/html/rfc4998">RFC 4998</a>:
 * Evidence Record Syntax (ERS)
 * <p>
 * <pre>
 * EvidenceRecord ::= SEQUENCE {
 *   version                   INTEGER { v1(1) } ,
 *   digestAlgorithms          SEQUENCE OF AlgorithmIdentifier,
 *   cryptoInfos               [0] CryptoInfos OPTIONAL,
 *   encryptionInfo            [1] EncryptionInfo OPTIONAL,
 *   archiveTimeStampSequence  ArchiveTimeStampSequence
 * }
 *
 * CryptoInfos ::= SEQUENCE SIZE (1..MAX) OF Attribute
 * </pre>
 */
public class EvidenceRecord extends ASN1Object
{

    /**
     * ERS {iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) ltans(11)
     * id-mod(0) id-mod-ers88(2) id-mod-ers88-v1(1) }
     */
    private static final ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(
        "1.3.6.1.5.5.11.0.2.1");

    private ASN1Integer version = new ASN1Integer(1);
    private ASN1Sequence digestAlgorithms;
    private CryptoInfos                 cryptoInfos;
    private EncryptionInfo              encryptionInfo;
    private ArchiveTimeStampSequence archiveTimeStampSequence;

    /**
     * Return an EvidenceRecord from the given object.
     *
     * @param obj the object we want converted.
     *
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an EvidenceRecord instance, or null.
     */
    public static EvidenceRecord getInstance (final Object obj)
    {
        if (obj == null || obj instanceof EvidenceRecord)
        {
            return (EvidenceRecord) obj;
        }
        else if (obj instanceof ASN1Sequence || obj instanceof byte[])
        {
            return new EvidenceRecord(ASN1Sequence.getInstance(obj));
        }

        throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName
            ());
    }

    protected EvidenceRecord(
        final ASN1Sequence digestAlgorithms,
        final CryptoInfos cryptoInfos,
        final EncryptionInfo encryptionInfo,
        final ArchiveTimeStampSequence archiveTimeStampSequence)
    {
        Enumeration digestAlgos = digestAlgorithms.getObjects();

        while (digestAlgos.hasMoreElements())
        {
            final Object digestAlgo = digestAlgos.nextElement();
            if (! (digestAlgo instanceof AlgorithmIdentifier))
            {
                throw new IllegalArgumentException("unknown object in getInstance: " +
                    digestAlgo.getClass().getName());
            }
        }

        this.digestAlgorithms = digestAlgorithms;
        this.cryptoInfos = cryptoInfos;
        this.encryptionInfo = encryptionInfo;
        this.archiveTimeStampSequence = archiveTimeStampSequence;
    }

    private EvidenceRecord (final ASN1Sequence sequence)
    {
        if (sequence.size() > 2 && sequence.size() < 6)
        {
            for (int i = 0; i != sequence.size(); i++)
            {
                ASN1Encodable object = sequence.getObjectAt(i);

                if (i == 0)
                {
                    if (object instanceof ASN1Integer)
                    {
                        final ASN1Integer versionNumber = ASN1Integer.getInstance(object);
                        if (versionNumber.getValue().compareTo(BigInteger.ONE) != 0)
                        {
                            throw new IllegalArgumentException("incompatible version");
                        }
                        else
                        {
                            this.version = versionNumber;
                        }
                    }
                    else
                    {
                        throw new IllegalArgumentException("unknown object in getInstance: " +
                            object.getClass().getName());
                    }
                }
                else if (i == 1)
                {
                    final Enumeration digestAlgos = ASN1Sequence.getInstance(object).getObjects();
                    final ASN1EncodableVector vector = new ASN1EncodableVector();

                    while (digestAlgos.hasMoreElements())
                    {
                        final Object digestAlgo = digestAlgos.nextElement();
                        vector.add(AlgorithmIdentifier.getInstance(digestAlgo));
                    }
                    digestAlgorithms = new DERSequence(vector);
                }
                else if (i == sequence.size() - 1)
                {
                    archiveTimeStampSequence = ArchiveTimeStampSequence.getInstance(sequence
                        .getObjectAt(sequence.size() - 1));
                }
                else
                {
                    if (object instanceof ASN1TaggedObject)
                    {
                        ASN1TaggedObject asn1TaggedObject = (ASN1TaggedObject) object;
                        switch (asn1TaggedObject.getTagNo())
                        {
                            case 0: cryptoInfos = CryptoInfos.getInstance(asn1TaggedObject
                                .getObject()); break;
                            case 1: encryptionInfo = EncryptionInfo.getInstance(asn1TaggedObject
                                .getObject()); break;
                        }
                    }
                    else
                    {
                        throw new IllegalArgumentException("unknown object in getInstance: " +
                            object.getClass().getName());
                    }
                }
            }
        }
        else
        {
            throw new IllegalArgumentException("wrong sequence size for an evidence record: " +
                sequence.size());
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        final ASN1EncodableVector vector = new ASN1EncodableVector();

        vector.add(version);
        vector.add(digestAlgorithms);

        if (null != cryptoInfos)
        {
            vector.add(cryptoInfos);
        }
        if (null != encryptionInfo)
        {
            vector.add(encryptionInfo);
        }

        vector.add(archiveTimeStampSequence);

        return new DERSequence(vector);
    }

    @Override
    public String toString ()
    {
        return ("EvidenceRecord: Oid(" + oid + ")");
    }

    protected void addDigestAlgorithmIdentifier(final AlgorithmIdentifier algId) {

        final ASN1EncodableVector vector = new ASN1EncodableVector();
        final Enumeration enumeration = this.digestAlgorithms.getObjects();
        boolean present = false;

        while (enumeration.hasMoreElements())
        {
            final AlgorithmIdentifier algorithmIdentifier = (AlgorithmIdentifier) enumeration
                .nextElement();
            vector.add(algorithmIdentifier);

            if (algorithmIdentifier.equals(algId))
            {
                present = true;
            }
        }

        if (! present)
        {
            vector.add(algId);
        }

        digestAlgorithms = new DERSequence(vector);
    }

    /**
     * Adds a new Archive TimeStamp to the Evidence Record
     * @param ats the archive timestamp to add
     * @param newSequence states whether this new archive timestamp must be added as part of a
     * new sequence (i.e. in the case of hashtree renewal) or not (i.e. in the case of timestamp
     * renewal)
     */
    protected void addArchiveTimeStamp(final ArchiveTimeStamp ats, final boolean newSequence)
    {
        if (newSequence)
        {
            final ArchiveTimeStampChain chain = ArchiveTimeStampChain.getInstance(ats);
            archiveTimeStampSequence.add(chain);
        }
        else
        {
            final int index = archiveTimeStampSequence.getArchiveTimeStampChains().size() - 1;
            final ArchiveTimeStampChain chain = ArchiveTimeStampChain.getInstance(
                archiveTimeStampSequence.getArchiveTimeStampChains().getObjectAt(index));
            chain.add(ats);
        }
    }

    protected ArchiveTimeStampSequence getArchiveTimeStampSequence() {
        return archiveTimeStampSequence;
    }


}
