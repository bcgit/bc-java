package org.bouncycastle.oer.its.ieee1609dot2;

import java.util.Iterator;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.OEROptional;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EncryptionKey;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId3;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Psid;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.SequenceOfHashedId3;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.ThreeDLocation;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Time64;

/**
 * <pre>
 *     HeaderInfo ::= SEQUENCE {
 *     psid                  Psid,
 *     generationTime        Time64 OPTIONAL,
 *     expiryTime            Time64  OPTIONAL,
 *     generationLocation    ThreeDLocation OPTIONAL,
 *     p2pcdLearningRequest  HashedId3 OPTIONAL,
 *     missingCrlIdentifier  MissingCrlIdentifier OPTIONAL,
 *     encryptionKey         EncryptionKey OPTIONAL,
 *     ...,
 *     inlineP2pcdRequest    SequenceOfHashedId3 OPTIONAL,
 *     requestedCertificate  Certificate OPTIONAL,
 *     pduFunctionalType     PduFunctionalType OPTIONAL,
 *     contributedExtensions ContributedExtensionBlocks OPTIONAL
 *     }
 * </pre>
 */
public class HeaderInfo
    extends ASN1Object
{
    private final Psid psid;
    private final Time64 generationTime;
    private final Time64 expiryTime;
    private final ThreeDLocation generationLocation;
    private final HashedId3 p2pcdLearningRequest;
    private final MissingCrlIdentifier missingCrlIdentifier;
    private final EncryptionKey encryptionKey;
    private final SequenceOfHashedId3 inlineP2pcdRequest;
    private final Certificate requestedCertificate;
    private final PduFunctionalType pduFunctionalType;
    private final ContributedExtensionBlocks contributedExtensions;


    private HeaderInfo(ASN1Sequence sequence)
    {
        if (sequence.size() != 11 && sequence.size() != 7)
        {
            throw new IllegalArgumentException("expected sequence size of 11 or 7");
        }

        Iterator<ASN1Encodable> it = sequence.iterator();

        psid = Psid.getInstance(it.next());
        generationTime = OEROptional.getValue(Time64.class, it.next());
        expiryTime = OEROptional.getValue(Time64.class, it.next());
        generationLocation = OEROptional.getValue(ThreeDLocation.class, it.next());
        p2pcdLearningRequest = OEROptional.getValue(HashedId3.class, it.next());
        missingCrlIdentifier = OEROptional.getValue(MissingCrlIdentifier.class, it.next());
        encryptionKey = OEROptional.getValue(EncryptionKey.class, it.next());
        if (sequence.size() > 7)
        {
            inlineP2pcdRequest = OEROptional.getValue(SequenceOfHashedId3.class, it.next());
            requestedCertificate = OEROptional.getValue(Certificate.class, it.next());
            pduFunctionalType = OEROptional.getValue(PduFunctionalType.class, it.next());
            contributedExtensions = OEROptional.getValue(ContributedExtensionBlocks.class, it.next());
        }
        else
        {
            inlineP2pcdRequest = null;
            requestedCertificate = null;
            pduFunctionalType = null;
            contributedExtensions = null;
        }
    }

    /**
     * @param psid
     * @param generationTime
     * @param expiryTime
     * @param generationLocation
     * @param p2pcdLearningRequest
     * @param missingCrlIdentifier
     * @param inlineP2pcdRequest
     * @param requestedCertificate
     * @param pduFunctionalType
     * @param contributedExtensions
     */
    public HeaderInfo(Psid psid,
                      Time64 generationTime,
                      Time64 expiryTime,
                      ThreeDLocation generationLocation,
                      HashedId3 p2pcdLearningRequest,
                      MissingCrlIdentifier missingCrlIdentifier,
                      EncryptionKey encryptionKey,
                      SequenceOfHashedId3 inlineP2pcdRequest,
                      Certificate requestedCertificate,
                      PduFunctionalType pduFunctionalType,
                      ContributedExtensionBlocks contributedExtensions)
    {
        this.psid = psid;
        this.generationTime = generationTime;
        this.expiryTime = expiryTime;
        this.generationLocation = generationLocation;
        this.p2pcdLearningRequest = p2pcdLearningRequest;
        this.missingCrlIdentifier = missingCrlIdentifier;
        this.encryptionKey = encryptionKey;
        this.inlineP2pcdRequest = inlineP2pcdRequest;
        this.requestedCertificate = requestedCertificate;
        this.pduFunctionalType = pduFunctionalType;
        this.contributedExtensions = contributedExtensions;
    }

    public static HeaderInfo getInstance(Object o)
    {
        if (o instanceof HeaderInfo)
        {
            return (HeaderInfo)o;
        }

        if (o != null)
        {
            return new HeaderInfo(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public Psid getPsid()
    {
        return psid;
    }

    public Time64 getGenerationTime()
    {
        return generationTime;
    }

    public Time64 getExpiryTime()
    {
        return expiryTime;
    }

    public ThreeDLocation getGenerationLocation()
    {
        return generationLocation;
    }

    public HashedId3 getP2pcdLearningRequest()
    {
        return p2pcdLearningRequest;
    }

    public MissingCrlIdentifier getMissingCrlIdentifier()
    {
        return missingCrlIdentifier;
    }

    public EncryptionKey getEncryptionKey()
    {
        return encryptionKey;
    }

    public SequenceOfHashedId3 getInlineP2pcdRequest()
    {
        return inlineP2pcdRequest;
    }

    public Certificate getRequestedCertificate()
    {
        return requestedCertificate;
    }

    public PduFunctionalType getPduFunctionalType()
    {
        return pduFunctionalType;
    }

    public ContributedExtensionBlocks getContributedExtensions()
    {
        return contributedExtensions;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{
            psid,
            OEROptional.getInstance(generationTime),
            OEROptional.getInstance(expiryTime),
            OEROptional.getInstance(generationLocation),
            OEROptional.getInstance(p2pcdLearningRequest),
            OEROptional.getInstance(missingCrlIdentifier),
            OEROptional.getInstance(encryptionKey),
            OEROptional.getInstance(inlineP2pcdRequest),
            OEROptional.getInstance(requestedCertificate),
            OEROptional.getInstance(pduFunctionalType),
            OEROptional.getInstance(contributedExtensions),
        });
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private Psid psid;
        private Time64 generationTime;
        private Time64 expiryTime;
        private ThreeDLocation generationLocation;
        private HashedId3 p2pcdLearningRequest;
        private MissingCrlIdentifier missingCrlIdentifier;
        private EncryptionKey encryptionKey;
        private SequenceOfHashedId3 inlineP2pcdRequest;
        private Certificate requestedCertificate;
        private PduFunctionalType pduFunctionalType;
        private ContributedExtensionBlocks contributedExtensions;

        public Builder setPsid(Psid psid)
        {
            this.psid = psid;
            return this;
        }

        public Builder setGenerationTime(Time64 generationTime)
        {
            this.generationTime = generationTime;
            return this;
        }

        public Builder setExpiryTime(Time64 expiryTime)
        {
            this.expiryTime = expiryTime;
            return this;
        }

        public Builder setGenerationLocation(ThreeDLocation generationLocation)
        {
            this.generationLocation = generationLocation;
            return this;
        }

        public Builder setP2pcdLearningRequest(HashedId3 p2pcdLearningRequest)
        {
            this.p2pcdLearningRequest = p2pcdLearningRequest;
            return this;
        }

        public Builder setEncryptionKey(EncryptionKey encryptionKey)
        {
            this.encryptionKey = encryptionKey;
            return this;
        }

        public Builder setMissingCrlIdentifier(MissingCrlIdentifier missingCrlIdentifier)
        {
            this.missingCrlIdentifier = missingCrlIdentifier;
            return this;
        }

        public Builder setInlineP2pcdRequest(SequenceOfHashedId3 inlineP2pcdRequest)
        {
            this.inlineP2pcdRequest = inlineP2pcdRequest;
            return this;
        }

        public Builder setRequestedCertificate(Certificate requestedCertificate)
        {
            this.requestedCertificate = requestedCertificate;
            return this;
        }

        public Builder setPduFunctionalType(PduFunctionalType pduFunctionalType)
        {
            this.pduFunctionalType = pduFunctionalType;
            return this;
        }

        public Builder setContributedExtensions(ContributedExtensionBlocks contributedExtensions)
        {
            this.contributedExtensions = contributedExtensions;
            return this;
        }

        public HeaderInfo createHeaderInfo()
        {
            return new HeaderInfo(
                psid,
                generationTime,
                expiryTime,
                generationLocation,
                p2pcdLearningRequest,
                missingCrlIdentifier,
                encryptionKey,
                inlineP2pcdRequest,
                requestedCertificate,
                pduFunctionalType,
                contributedExtensions);
        }
    }


}