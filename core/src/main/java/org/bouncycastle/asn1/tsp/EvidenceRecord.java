package org.bouncycastle.asn1.tsp;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

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
public class EvidenceRecord
    extends ASN1Object
{

    /**
     * ERS {iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) ltans(11)
     * id-mod(0) id-mod-ers88(2) id-mod-ers88-v1(1) }
     */
    private static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.3.6.1.5.5.11.0.2.1");

    private ASN1Integer version = new ASN1Integer(1);
    private ASN1Sequence digestAlgorithms;
    private CryptoInfos cryptoInfos;
    private EncryptionInfo encryptionInfo;
    private ArchiveTimeStampSequence archiveTimeStampSequence;

    /**
     * Return an EvidenceRecord from the given object.
     *
     * @param obj the object we want converted.
     * @return an EvidenceRecord instance, or null.
     * @throws IllegalArgumentException if the object cannot be converted.
     */
    public static EvidenceRecord getInstance(final Object obj)
    {
        if (obj instanceof EvidenceRecord)
        {
            return (EvidenceRecord)obj;
        }
        else if (obj != null)
        {
            return new EvidenceRecord(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static EvidenceRecord getInstance(ASN1TaggedObject tagged, boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(tagged, explicit));
    }

    private EvidenceRecord(
        EvidenceRecord evidenceRecord,
        ArchiveTimeStampSequence replacementSequence,
        ArchiveTimeStamp newChainTimeStamp)
    {
        this.version = evidenceRecord.version;

        // check the list of digest algorithms is correct.
        if (newChainTimeStamp != null)
        {
            AlgorithmIdentifier algId = newChainTimeStamp.getDigestAlgorithmIdentifier();
            final ASN1EncodableVector vector = new ASN1EncodableVector();
            final Enumeration enumeration = evidenceRecord.digestAlgorithms.getObjects();
            boolean found = false;

            while (enumeration.hasMoreElements())
            {
                final AlgorithmIdentifier algorithmIdentifier = AlgorithmIdentifier.getInstance(
                                                                            enumeration.nextElement());
                vector.add(algorithmIdentifier);

                if (algorithmIdentifier.equals(algId))
                {
                    found = true;
                    break;
                }
            }

            if (!found)
            {
                vector.add(algId);
                this.digestAlgorithms = new DERSequence(vector);
            }
            else
            {
                this.digestAlgorithms = evidenceRecord.digestAlgorithms;
            }
        }
        else
        {
            this.digestAlgorithms = evidenceRecord.digestAlgorithms;
        }

        this.cryptoInfos = evidenceRecord.cryptoInfos;
        this.encryptionInfo = evidenceRecord.encryptionInfo;
        this.archiveTimeStampSequence = replacementSequence;
    }

    public EvidenceRecord(
        AlgorithmIdentifier[] digestAlgorithms,
        CryptoInfos cryptoInfos,
        EncryptionInfo encryptionInfo,
        ArchiveTimeStampSequence archiveTimeStampSequence)
    {
        this.digestAlgorithms = new DERSequence(digestAlgorithms);
        this.cryptoInfos = cryptoInfos;
        this.encryptionInfo = encryptionInfo;
        this.archiveTimeStampSequence = archiveTimeStampSequence;
    }

    private EvidenceRecord(final ASN1Sequence sequence)
    {
        if (sequence.size() < 3 && sequence.size() > 5)
        {
            throw new IllegalArgumentException("wrong sequence size in constructor: " + sequence.size());
        }

        final ASN1Integer versionNumber = ASN1Integer.getInstance(sequence.getObjectAt(0));
        if (versionNumber.intValueExact() != 1)
        {
            throw new IllegalArgumentException("incompatible version");
        }

        this.version = versionNumber;

        this.digestAlgorithms = ASN1Sequence.getInstance(sequence.getObjectAt(1));
        for (int i = 2; i != sequence.size() - 1; i++)
        {
            ASN1Encodable object = sequence.getObjectAt(i);

            if (object instanceof ASN1TaggedObject)
            {
                ASN1TaggedObject asn1TaggedObject = (ASN1TaggedObject)object;
                switch (asn1TaggedObject.getTagNo())
                {
                case 0:
                    cryptoInfos = CryptoInfos.getInstance(asn1TaggedObject, false);
                    break;
                case 1:
                    encryptionInfo = EncryptionInfo.getInstance(asn1TaggedObject, false);
                    break;
                default:
                    throw new IllegalArgumentException("unknown tag in getInstance: " + asn1TaggedObject.getTagNo());
                }
            }
            else
            {
                throw new IllegalArgumentException("unknown object in getInstance: " +
                    object.getClass().getName());
            }
        }
        archiveTimeStampSequence = ArchiveTimeStampSequence.getInstance(sequence.getObjectAt(sequence.size() - 1));
    }

    public AlgorithmIdentifier[] getDigestAlgorithms()
    {
        AlgorithmIdentifier[] rv = new AlgorithmIdentifier[digestAlgorithms.size()];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = AlgorithmIdentifier.getInstance(digestAlgorithms.getObjectAt(i));
        }

        return rv;
    }

    public ArchiveTimeStampSequence getArchiveTimeStampSequence()
    {
        return archiveTimeStampSequence;
    }

    /**
     * Return a new EvidenceRecord with an added ArchiveTimeStamp
     *
     * @param ats         the archive timestamp to add
     * @param newChain states whether this new archive timestamp must be added as part of a
     *                    new sequence (i.e. in the case of hashtree renewal) or not (i.e. in the case of timestamp
     *                    renewal)
     * @return the new EvidenceRecord
     */
    public EvidenceRecord addArchiveTimeStamp(final ArchiveTimeStamp ats, final boolean newChain)
    {
        if (newChain)
        {
            ArchiveTimeStampChain chain = new ArchiveTimeStampChain(ats);
            
            return new EvidenceRecord(this, archiveTimeStampSequence.append(chain), ats);
        }
        else
        {
            ArchiveTimeStampChain[] chains = archiveTimeStampSequence.getArchiveTimeStampChains();

            chains[chains.length - 1] = chains[chains.length - 1].append(ats);
            return new EvidenceRecord(this, new ArchiveTimeStampSequence(chains), null);
        }
    }

    public String toString()
    {
        return ("EvidenceRecord: Oid(" + OID + ")");
    }

    public ASN1Primitive toASN1Primitive()
    {
        final ASN1EncodableVector vector = new ASN1EncodableVector(5);

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
}
