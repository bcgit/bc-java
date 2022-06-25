package org.bouncycastle.tsp.ers;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.tsp.ArchiveTimeStamp;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampChain;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampSequence;
import org.bouncycastle.asn1.tsp.EvidenceRecord;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;

/**
 * RFC 4998 Evidence Record.
 */
public class ERSEvidenceRecord
{
    private final EvidenceRecord evidenceRecord;
    private final DigestCalculatorProvider digestCalculatorProvider;
    private final ERSArchiveTimeStamp firstArchiveTimeStamp;
    private final ERSArchiveTimeStamp lastArchiveTimeStamp;

    public ERSEvidenceRecord(byte[] evidenceRecord, DigestCalculatorProvider digestCalculatorProvider)
        throws TSPException, ERSException
    {
        this(EvidenceRecord.getInstance(evidenceRecord), digestCalculatorProvider);
    }

    public ERSEvidenceRecord(EvidenceRecord evidenceRecord, DigestCalculatorProvider digestCalculatorProvider)
        throws TSPException, ERSException
    {
        this.evidenceRecord = evidenceRecord;
        this.digestCalculatorProvider = digestCalculatorProvider;

        ArchiveTimeStampSequence sequence = evidenceRecord.getArchiveTimeStampSequence();
        ArchiveTimeStampChain[] chains = sequence.getArchiveTimeStampChains();
        ArchiveTimeStampChain chain = chains[chains.length - 1];
        ArchiveTimeStamp[] archiveTimestamps = chain.getArchiveTimestamps();

        this.firstArchiveTimeStamp = new ERSArchiveTimeStamp(archiveTimestamps[0], digestCalculatorProvider);
        this.lastArchiveTimeStamp = new ERSArchiveTimeStamp(archiveTimestamps[archiveTimestamps.length - 1], digestCalculatorProvider);
    }

    public ERSArchiveTimeStamp getLastArchiveTimeStamp()
    {
        return lastArchiveTimeStamp;
    }

    ArchiveTimeStamp[] getArchiveTimeStamps()
    {
        ArchiveTimeStampSequence sequence = evidenceRecord.getArchiveTimeStampSequence();
        ArchiveTimeStampChain[] chains = sequence.getArchiveTimeStampChains();
        ArchiveTimeStampChain chain = chains[chains.length - 1];

        return chain.getArchiveTimestamps();
    }

    public void validatePresent(ERSData data, Date atDate)
        throws ERSException, OperatorCreationException
    {
        firstArchiveTimeStamp.validatePresent(data, atDate);
    }

    public void validatePresent(byte[] hash, Date atDate)
        throws ERSException, OperatorCreationException
    {
        firstArchiveTimeStamp.validatePresent(hash, atDate);
    }

    /**
     * Return the TimeStamp signing certificate if it is present.
     *
     * @return the TimeStamp signing certificate.
     */
    public X509CertificateHolder getSigningCertificate()
    {
        return lastArchiveTimeStamp.getSigningCertificate();
    }

    /**
     * Validate the time stamp associated with this ArchiveTimeStamp.
     *
     * @param verifier signer verifier for the contained time stamp.
     * @throws TSPException in case of validation failure or error.
     */
    public void validate(SignerInformationVerifier verifier)
        throws TSPException
    {
        // check if we have more than 1 ArchiveTimeStamp in the chain
        if (firstArchiveTimeStamp != lastArchiveTimeStamp)
        {
             ArchiveTimeStamp[] archiveTimeStamps = getArchiveTimeStamps();
             for (int i = 0; i != archiveTimeStamps.length - 1; i++)
             {
                 try
                 {
                     lastArchiveTimeStamp.validatePresent(new ERSByteData(archiveTimeStamps[i].getTimeStamp().getEncoded(ASN1Encoding.DER)), lastArchiveTimeStamp.getGenTime());
                 }
                 catch (Exception e)
                 {
                     throw new TSPException("unable to process previous ArchiveTimeStamps", e);
                 }
             }
        }
        lastArchiveTimeStamp.validate(verifier);
    }

    public EvidenceRecord toASN1Structure()
    {
        return evidenceRecord;
    }

    /**
     * return the ASN.1 encoded representation of this object.
     */
    public byte[] getEncoded()
        throws IOException
    {
        return evidenceRecord.getEncoded();
    }

    public TimeStampRequest generateTimeStampRenewalRequest(TimeStampRequestGenerator tspReqGen)
        throws TSPException, ERSException, IOException
    {
        ERSArchiveTimeStampGenerator atsGen = buildTspRenewalGenerator();

        return atsGen.generateTimeStampRequest(tspReqGen);
    }

    public TimeStampRequest generateTimeStampRenewalRequest(TimeStampRequestGenerator tspReqGen, BigInteger nonce)
        throws ERSException, TSPException, IOException
    {
        ERSArchiveTimeStampGenerator atsGen = buildTspRenewalGenerator();

        return atsGen.generateTimeStampRequest(tspReqGen, nonce);
    }

    public ERSEvidenceRecord renewTimeStamp(TimeStampResponse tspResp)
        throws ERSException, TSPException
    {
        ERSArchiveTimeStampGenerator atsGen = buildTspRenewalGenerator();

        ArchiveTimeStamp ats = atsGen.generateArchiveTimeStamp(tspResp).toASN1Structure();
   
        try
        {
            return new ERSEvidenceRecord(evidenceRecord.addArchiveTimeStamp(ats, false), digestCalculatorProvider);
        }
        catch (IllegalArgumentException e)
        {
            throw new ERSException(e.getMessage(), e);
        }
    }

    private ERSArchiveTimeStampGenerator buildTspRenewalGenerator()
        throws ERSException
    {
        DigestCalculator digCalc;
        try
        {
            digCalc = digestCalculatorProvider.get(lastArchiveTimeStamp.getDigestAlgorithmIdentifier());
        }
        catch (OperatorCreationException e)
        {
            throw new ERSException(e.getMessage(), e);
        }

        ArchiveTimeStamp[] previous = this.getArchiveTimeStamps();

        if (!digCalc.getAlgorithmIdentifier().equals(previous[0].getDigestAlgorithmIdentifier()))
        {
            throw new ERSException("digest mismatch for timestamp renewal");
        }

        ERSArchiveTimeStampGenerator atsGen = new ERSArchiveTimeStampGenerator(digCalc);

        for (int i = 0; i != previous.length; i++)
        {
            try
            {
                atsGen.addData(new ERSByteData(previous[i].getTimeStamp().getEncoded(ASN1Encoding.DER)));
            }
            catch (IOException e)
            {
                throw new ERSException("unable to process previous ArchiveTimeStamps", e);
            }
        }

        return atsGen;
    }
}
