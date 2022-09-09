package org.bouncycastle.tsp.ers;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.tsp.ArchiveTimeStamp;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampChain;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampSequence;
import org.bouncycastle.asn1.tsp.EvidenceRecord;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.util.io.Streams;

/**
 * RFC 4998 Evidence Record.
 */
public class ERSEvidenceRecord
{
    private final EvidenceRecord evidenceRecord;
    private final DigestCalculatorProvider digestCalculatorProvider;
    private final ERSArchiveTimeStamp firstArchiveTimeStamp;
    private final ERSArchiveTimeStamp lastArchiveTimeStamp;
    private final byte[] previousChainsDigest;
    private final DigestCalculator digCalc;
    private final ArchiveTimeStamp primaryArchiveTimeStamp;

    public ERSEvidenceRecord(InputStream ersIn, DigestCalculatorProvider digestCalculatorProvider)
        throws TSPException, ERSException, IOException
    {
        this(EvidenceRecord.getInstance(Streams.readAll(ersIn)), digestCalculatorProvider);
    }

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
        this.primaryArchiveTimeStamp = chains[0].getArchiveTimestamps()[0];
        
        // Section 5.3 Part 2. - check chains.
        validateChains(chains);

        ArchiveTimeStampChain chain = chains[chains.length - 1];
        ArchiveTimeStamp[] archiveTimestamps = chain.getArchiveTimestamps();

        this.lastArchiveTimeStamp = new ERSArchiveTimeStamp(archiveTimestamps[archiveTimestamps.length - 1], digestCalculatorProvider);

        if (chains.length > 1)
        {
            try
            {
                ASN1EncodableVector v = new ASN1EncodableVector();
                for (int i = 0; i != chains.length - 1; i++)
                {
                    v.add(chains[i]);
                }

                this.digCalc = digestCalculatorProvider.get(lastArchiveTimeStamp.getDigestAlgorithmIdentifier());
                OutputStream dOut = digCalc.getOutputStream();

                dOut.write(new DERSequence(v).getEncoded(ASN1Encoding.DER));
                dOut.close();

                this.previousChainsDigest = digCalc.getDigest();
            }
            catch (Exception e)
            {
                 throw new ERSException(e.getMessage(), e);
            }
        }
        else
        {
            this.digCalc = null;
            this.previousChainsDigest = null;
        }

        this.firstArchiveTimeStamp = new ERSArchiveTimeStamp(previousChainsDigest, archiveTimestamps[0], digestCalculatorProvider);
    }

    private void validateChains(ArchiveTimeStampChain[] chains)
        throws ERSException, TSPException
    {
        for (int i = 0; i != chains.length; i++)
        {
            ArchiveTimeStamp[] archiveTimeStamps = chains[i].getArchiveTimestamps();
            ArchiveTimeStamp prevArchiveTimeStamp = archiveTimeStamps[0];
            AlgorithmIdentifier digAlg = archiveTimeStamps[0].getDigestAlgorithmIdentifier();
            for (int j = 1; j != archiveTimeStamps.length; j++)
            {
                // TODO: check time stamp date - don't think this can be done here.
                ArchiveTimeStamp archiveTimeStamp = archiveTimeStamps[j];

                // check digest algorithm consistent.
                if (!digAlg.equals(archiveTimeStamp.getDigestAlgorithmIdentifier()))
                {
                    throw new ERSException("invalid digest algorithm in chain");
                }

                ContentInfo timeStamp = archiveTimeStamp.getTimeStamp();
                TSTInfo tstData;
                if (timeStamp.getContentType().equals(CMSObjectIdentifiers.signedData))
                {
                    tstData = extractTimeStamp(timeStamp);
                }
                else
                {
                    throw new TSPException("cannot identify TSTInfo");
                }

                try
                {
                    DigestCalculator digCalc = digestCalculatorProvider.get(digAlg);
                    ERSArchiveTimeStamp ersArchiveTimeStamp = new ERSArchiveTimeStamp(archiveTimeStamp, digCalc);

                    ersArchiveTimeStamp.validatePresent(new ERSByteData(prevArchiveTimeStamp.getTimeStamp().getEncoded(ASN1Encoding.DER)), tstData.getGenTime().getDate());
                }
                catch (Exception e)
                {
                     throw new ERSException("invalid timestamp renewal found: " + e.getMessage(), e);
                }

                prevArchiveTimeStamp = archiveTimeStamp;
            }
        }
    }

    ArchiveTimeStamp[] getArchiveTimeStamps()
    {
        ArchiveTimeStampSequence sequence = evidenceRecord.getArchiveTimeStampSequence();
        ArchiveTimeStampChain[] chains = sequence.getArchiveTimeStampChains();
        ArchiveTimeStampChain chain = chains[chains.length - 1];

        return chain.getArchiveTimestamps();
    }

    /**
     * Return the timestamp imprint for the initial ArchiveTimeStamp in this evidence record.
     *
     * @return initial hash root.
     */
    public byte[] getPrimaryRootHash()
        throws TSPException, ERSException
    {
        ContentInfo timeStamp = primaryArchiveTimeStamp.getTimeStamp();

        if (timeStamp.getContentType().equals(CMSObjectIdentifiers.signedData))
        {
            TSTInfo tstData = extractTimeStamp(timeStamp);

            return tstData.getMessageImprint().getHashedMessage();
        }
        else
        {
            throw new ERSException("cannot identify TSTInfo for digest");
        }
    }

    private TSTInfo extractTimeStamp(ContentInfo timeStamp)
        throws TSPException
    {
        SignedData tsData = SignedData.getInstance(timeStamp.getContent());
        if (tsData.getEncapContentInfo().getContentType().equals(PKCSObjectIdentifiers.id_ct_TSTInfo))
        {
            TSTInfo tstData = TSTInfo.getInstance(
                ASN1OctetString.getInstance(tsData.getEncapContentInfo().getContent()).getOctets());

            return tstData;
        }
        else
        {
            throw new TSPException("cannot parse time stamp");
        }
    }

    /**
     * Return true if this evidence record is related to the passed in one.
     *
     * @param er the evidence record to be checked.
     * @return true if the primary time stamp has the same value, false otherwise.
     */
    public boolean isRelatedTo(ERSEvidenceRecord er)
    {
        return this.primaryArchiveTimeStamp.getTimeStamp().equals(er.primaryArchiveTimeStamp.getTimeStamp());
    }

    /**
     * Return true if the hash of data appears in the primary archive time stamp for the current chain.
     *
     * @param data the data of interest.
     * @return
     */
    public boolean isContaining(ERSData data, Date date)
        throws ERSException
    {
         return firstArchiveTimeStamp.isContaining(data, date);
    }

    /**
     * Validate that a particular data object/group is present.
     *
     * @param data the data object/group.
     * @param atDate date at which data is supposed to be valid.
     * @throws ERSException if the object cannot be found or the record is invalid.
     */
    public void validatePresent(ERSData data, Date atDate)
        throws ERSException
    {
        // TODO: need to use date to check back
        firstArchiveTimeStamp.validatePresent(data, atDate);
    }

    /**
     * Validate that a particular data object/group is present by hash.
     *
     * @param isDataGroup true if hash represents a data group.
     * @param hash expected hash value
     * @param atDate date at which value is supposed to be valid.
     * @throws ERSException if the object cannot be found or the record is invalid.
     */
    public void validatePresent(boolean isDataGroup, byte[] hash, Date atDate)
        throws ERSException
    {
        // TODO: need to use date to check back
        firstArchiveTimeStamp.validatePresent(isDataGroup, hash, atDate);
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
     * Validate the current time stamp associated with this evidence record.
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
        throws TSPException, ERSException
    {
        return generateTimeStampRenewalRequest(tspReqGen, null);
    }

    public TimeStampRequest generateTimeStampRenewalRequest(TimeStampRequestGenerator tspReqGen, BigInteger nonce)
        throws ERSException, TSPException
    {
        ERSArchiveTimeStampGenerator atsGen = buildTspRenewalGenerator();

        try
        {
            return atsGen.generateTimeStampRequest(tspReqGen, nonce);
        }
        catch (IOException e)
        {
            throw new ERSException(e.getMessage(), e);
        }
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
        
        List<ERSData> prevTimes = new ArrayList<ERSData>(previous.length);   
        for (int i = 0; i != previous.length; i++)
        {
            try
            {
                prevTimes.add(new ERSByteData(previous[i].getTimeStamp().getEncoded(ASN1Encoding.DER)));
            }
            catch (IOException e)
            {
                throw new ERSException("unable to process previous ArchiveTimeStamps", e);
            }
        }
        ERSDataGroup timestampGroup = new ERSDataGroup(prevTimes);
        
        atsGen.addData(timestampGroup);

        return atsGen;
    }

    public TimeStampRequest generateHashRenewalRequest(DigestCalculator digCalc, ERSData data, TimeStampRequestGenerator tspReqGen)
        throws ERSException, TSPException, IOException
    {
        return generateHashRenewalRequest(digCalc, data, tspReqGen, null);
    }

    public TimeStampRequest generateHashRenewalRequest(DigestCalculator digCalc, ERSData data, TimeStampRequestGenerator tspReqGen, BigInteger nonce)
        throws ERSException, TSPException, IOException
    {
        // check old data present
        try
        {
            firstArchiveTimeStamp.validatePresent(data, new Date());
        }
        catch (Exception e)
        {
            throw new ERSException("attempt to hash renew on invalid data");
        }
        
        ERSArchiveTimeStampGenerator atsGen = new ERSArchiveTimeStampGenerator(digCalc);

        atsGen.addData(data);
        
        atsGen.addPreviousChains(evidenceRecord.getArchiveTimeStampSequence());
        
        return atsGen.generateTimeStampRequest(tspReqGen, nonce);
    }

    public ERSEvidenceRecord renewHash(DigestCalculator digCalc, ERSData data, TimeStampResponse tspResp)
        throws ERSException, TSPException
    {
        // check old data present
        try
        {
            firstArchiveTimeStamp.validatePresent(data, new Date());
        }
        catch (Exception e)
        {
            throw new ERSException("attempt to hash renew on invalid data");
        }

        try
        {
            ERSArchiveTimeStampGenerator atsGen = new ERSArchiveTimeStampGenerator(digCalc);

            atsGen.addData(data);

            atsGen.addPreviousChains(evidenceRecord.getArchiveTimeStampSequence());

            ArchiveTimeStamp ats = atsGen.generateArchiveTimeStamp(tspResp).toASN1Structure();

            return new ERSEvidenceRecord(evidenceRecord.addArchiveTimeStamp(ats, true), digestCalculatorProvider);
        }
        catch (IOException e)
        {
            throw new ERSException(e.getMessage(), e);
        }
        catch (IllegalArgumentException e)
        {
            throw new ERSException(e.getMessage(), e);
        }
    }

    DigestCalculatorProvider getDigestAlgorithmProvider()
    {
        return digestCalculatorProvider;
    }
}
