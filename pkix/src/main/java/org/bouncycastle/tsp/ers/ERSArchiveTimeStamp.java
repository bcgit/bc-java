package org.bouncycastle.tsp.ers;

import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.NoSuchElementException;

import org.bouncycastle.asn1.tsp.ArchiveTimeStamp;
import org.bouncycastle.asn1.tsp.PartialHashtree;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Store;

/**
 * Carrier for an RFC 4998 ArchiveTimeStamp - an RFC 3161 time-stamp token
 * together with the reduced hash tree (a sequence of PartialHashtrees) that
 * binds a particular data object or data group to the time-stamped root hash.
 * Provides operations to recover the root hash, confirm a data object is
 * present, and validate the underlying time-stamp signature.
 */
public class ERSArchiveTimeStamp
{
    private final ArchiveTimeStamp archiveTimeStamp;
    private final DigestCalculator digCalc;
    private final TimeStampToken timeStampToken;
    private final byte[] previousChainsDigest;

    private ERSRootNodeCalculator rootNodeCalculator = new BinaryTreeRootCalculator();

    /**
     * Create an archive time-stamp from an encoded ArchiveTimeStamp.
     *
     * @param archiveTimeStamp the DER encoded ArchiveTimeStamp.
     * @param digCalcProv provider for the digest calculator matching the structure's digest algorithm.
     */
    public ERSArchiveTimeStamp(byte[] archiveTimeStamp, DigestCalculatorProvider digCalcProv)
        throws TSPException, ERSException
    {
        this(parseArchiveTimeStamp(archiveTimeStamp), digCalcProv);
    }

    private static ArchiveTimeStamp parseArchiveTimeStamp(byte[] archiveTimeStamp)
        throws ERSException
    {
        try
        {
            return ArchiveTimeStamp.getInstance(archiveTimeStamp);
        }
        catch (IllegalArgumentException e)
        {
            throw new ERSException("malformed archive time stamp: " + e.getMessage(), e);
        }
        catch (IllegalStateException e)
        {
            throw new ERSException("malformed archive time stamp: " + e.getMessage(), e);
        }
        catch (NoSuchElementException e)
        {
            throw new ERSException("malformed archive time stamp: " + e.getMessage(), e);
        }
        catch (ArrayIndexOutOfBoundsException e)
        {
            throw new ERSException("malformed archive time stamp: " + e.getMessage(), e);
        }
    }

    /**
     * Create an archive time-stamp from a parsed ArchiveTimeStamp structure.
     *
     * @param archiveTimeStamp the ArchiveTimeStamp to wrap.
     * @param digCalcProv provider for the digest calculator matching the structure's digest algorithm.
     */
    public ERSArchiveTimeStamp(ArchiveTimeStamp archiveTimeStamp, DigestCalculatorProvider digCalcProv)
        throws TSPException, ERSException
    {
        this.previousChainsDigest = null;
        try
        {
            this.archiveTimeStamp = archiveTimeStamp;
            this.timeStampToken = new TimeStampToken(archiveTimeStamp.getTimeStamp());
            this.digCalc = digCalcProv.get(archiveTimeStamp.getDigestAlgorithmIdentifier());
        }
        catch (IOException e)
        {
            throw new ERSException(e.getMessage(), e);
        }
        catch (OperatorCreationException e)
        {
            throw new ERSException(e.getMessage(), e);
        }
    }

    ERSArchiveTimeStamp(ArchiveTimeStamp archiveTimeStamp, DigestCalculator digCalc)
        throws TSPException, ERSException
    {
        this.previousChainsDigest = null;
        try
        {
            this.archiveTimeStamp = archiveTimeStamp;
            this.timeStampToken = new TimeStampToken(archiveTimeStamp.getTimeStamp());
            this.digCalc = digCalc;
        }
        catch (IOException e)
        {
            throw new ERSException(e.getMessage(), e);
        }
    }

    ERSArchiveTimeStamp(byte[] previousChainsDigest, ArchiveTimeStamp archiveTimeStamp, DigestCalculatorProvider digCalcProv)
        throws TSPException, ERSException
    {
        this.previousChainsDigest = previousChainsDigest;
        try
        {
            this.archiveTimeStamp = archiveTimeStamp;
            this.timeStampToken = new TimeStampToken(archiveTimeStamp.getTimeStamp());
            this.digCalc = digCalcProv.get(archiveTimeStamp.getDigestAlgorithmIdentifier());
        }
        catch (IOException e)
        {
            throw new ERSException(e.getMessage(), e);
        }
        catch (OperatorCreationException e)
        {
            throw new ERSException(e.getMessage(), e);
        }
    }

    public AlgorithmIdentifier getDigestAlgorithmIdentifier()
    {
        return archiveTimeStamp.getDigestAlgorithmIdentifier();
    }

    /**
     * Validate that the passed in data object/group is present in this archive
     * time-stamp at the given date - that its hash appears in the reduced hash
     * tree and the recovered root hash matches the time-stamp imprint.
     *
     * @param data the data object or data group to check for.
     * @param atDate date the data is expected to be valid at; the time-stamp must not be in the future relative to it.
     * @throws ERSException if the data is not present, or the time-stamp generation time is after atDate.
     */
    public void validatePresent(ERSData data, Date atDate)
        throws ERSException
    {
        validatePresent(data instanceof ERSDataGroup, data.getHash(digCalc, previousChainsDigest), atDate);
    }

    /**
     * Return true if the passed in data object/group is present in this archive
     * time-stamp at the given date. Equivalent to {@link #validatePresent(ERSData, Date)}
     * but returning a boolean rather than throwing on absence.
     *
     * @param data the data object or data group to check for.
     * @param atDate date the data is expected to be valid at.
     * @return true if the data is present, false otherwise.
     * @throws ArchiveTimeStampValidationException if the time-stamp generation time is after atDate.
     */
    public boolean isContaining(ERSData data, Date atDate)
        throws ERSException
    {
        if (timeStampToken.getTimeStampInfo().getGenTime().after(atDate))
        {
            throw new ArchiveTimeStampValidationException("timestamp generation time is in the future");
        }

        try
        {
            validatePresent(data, atDate);

            return true;
        }
        catch (Exception e)
        {
            return false;
        }
    }

    /**
     * Validate that data with the given hash is present in this archive time-stamp
     * at the given date.
     *
     * @param isDataGroup true if the hash represents a data group rather than a single object.
     * @param hash the (pre-computed) hash of the data object/group to check for.
     * @param atDate date the data is expected to be valid at.
     * @throws ERSException if the hash is not present, or the time-stamp generation time is after atDate.
     */
    public void validatePresent(boolean isDataGroup, byte[] hash, Date atDate)
        throws ERSException
    {
        if (timeStampToken.getTimeStampInfo().getGenTime().after(atDate))
        {
            throw new ArchiveTimeStampValidationException("timestamp generation time is in the future");
        }

        checkContainsHashValue(isDataGroup, hash, digCalc);

        PartialHashtree[] partialTree = archiveTimeStamp.getReducedHashTree();
        byte[] rootHash;

        if (partialTree != null)
        {
            rootHash = rootNodeCalculator.recoverRootHash(digCalc, archiveTimeStamp.getReducedHashTree());
        }
        else
        {
            rootHash = hash;
        }

        checkTimeStampValid(timeStampToken, rootHash);
    }

    public TimeStampToken getTimeStampToken()
    {
        return timeStampToken;
    }

    /**
     * Return the TimeStamp signing certificate if it is present.
     *
     * @return the TimeStamp signing certificate.
     */
    public X509CertificateHolder getSigningCertificate()
    {
        final Store<X509CertificateHolder> certificateStore = timeStampToken.getCertificates();
        if (certificateStore != null)
        {
            final Collection<X509CertificateHolder> certs = certificateStore.getMatches(timeStampToken.getSID());
            if (!certs.isEmpty())
            {
                return (X509CertificateHolder)certs.iterator().next();
            }
        }

        return null;
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
        timeStampToken.validate(verifier);
    }

    void checkContainsHashValue(boolean isGroup, final byte[] hash, final DigestCalculator digCalc)
        throws ArchiveTimeStampValidationException
    {
        PartialHashtree[] reducedHashTree = archiveTimeStamp.getReducedHashTree();

        if (reducedHashTree != null)
        {
            // RFC 4998, Section 4.3, part 2, search first node only.
            PartialHashtree current = reducedHashTree[0];

            if (!isGroup && current.containsHash(hash))
            {
                return;
            }
            // check we're not a composite document hash
            if (current.getValueCount() > 1)
            {
                if (Arrays.areEqual(hash, ERSUtil.calculateBranchHash(digCalc, current.getValues())))
                {
                    return;
                }
            }
            throw new ArchiveTimeStampValidationException("object hash not found");
        }
        else
        {
            if (!Arrays.areEqual(hash, timeStampToken.getTimeStampInfo().getMessageImprintDigest()))
            {
                throw new ArchiveTimeStampValidationException("object hash not found in wrapped timestamp");
            }
        }
    }

    void checkTimeStampValid(final TimeStampToken timeStampToken, final byte[] hash)
        throws ArchiveTimeStampValidationException
    {
        if (hash != null)
        {
            if (!Arrays.areEqual(hash, timeStampToken.getTimeStampInfo().getMessageImprintDigest()))
            {
                throw new ArchiveTimeStampValidationException("timestamp hash does not match root");
            }
        }
    }

    /**
     * Return the generation time of the time-stamp associated with
     * this archive time stamp.
     *
     * @return the time the associated time-stamp was created.
     */
    public Date getGenTime()
    {
        return timeStampToken.getTimeStampInfo().getGenTime();
    }

    /**
     * Return the not-after date for the time-stamp's signing certificate
     * if it is present.
     *
     * @return the issuing TSP server not-after date, or null if not present.
     */
    public Date getExpiryTime()
    {
        X509CertificateHolder crtHolder = getSigningCertificate();
        if (crtHolder != null)
        {
            return crtHolder.getNotAfter();
        }
        return null;
    }

    /**
     * Return the underlying ASN.1 ArchiveTimeStamp structure.
     *
     * @return the ArchiveTimeStamp this object wraps.
     */
    public ArchiveTimeStamp toASN1Structure()
    {
        return archiveTimeStamp;
    }

    /**
     * return the ASN.1 encoded representation of this object.
     */
    public byte[] getEncoded()
        throws IOException
    {
        return archiveTimeStamp.getEncoded();
    }

    /**
     * Build an ArchiveTimeStamp from a regular time stamp token.
     *
     * @param tspToken the TimeStampToken in the regular time stamp.
     * @param digCalcProv a digest calculator provider for use with the time stamp.
     * @return an ERSArchiveTimeStamp containing the time stamp.
     * @throws TSPException on a failure to parse the time stamp token data.
     * @throws ERSException on a failure to convert the time stamp token to an archive time stamp.
     */
    public static ERSArchiveTimeStamp fromTimeStampToken(TimeStampToken tspToken, DigestCalculatorProvider digCalcProv)
        throws TSPException, ERSException
    {
        return new ERSArchiveTimeStamp(new ArchiveTimeStamp(tspToken.toCMSSignedData().toASN1Structure()), digCalcProv);
    }
}
