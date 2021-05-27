package org.bouncycastle.tsp.ers;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Collection;
import java.util.Date;

import org.bouncycastle.asn1.tsp.ArchiveTimeStamp;
import org.bouncycastle.asn1.tsp.PartialHashtree;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.selector.X509CertificateHolderSelector;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Store;

/**
 * RFC 4998 ArchiveTimeStamp.
 */
public class ERSArchiveTimeStamp
{
    private final ArchiveTimeStamp archiveTimeStamp;
    private final DigestCalculator digCalc;
    private final TimeStampToken timeStampToken;

    public ERSArchiveTimeStamp(byte[] archiveTimeStamp, DigestCalculatorProvider digCalcProv)
        throws TSPException, ERSException
    {
        this(ArchiveTimeStamp.getInstance(archiveTimeStamp), digCalcProv);
    }

    public ERSArchiveTimeStamp(ArchiveTimeStamp archiveTimeStamp, DigestCalculatorProvider digCalcProv)
        throws TSPException, ERSException
    {
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

    public AlgorithmIdentifier getDigestAlgorithmIdentifier()
    {
        return archiveTimeStamp.getDigestAlgorithmIdentifier();
    }

    public void validatePresent(ERSData data, Date atDate)
        throws ERSException, OperatorCreationException
    {
        validatePresent(data.getHash(digCalc), atDate);
    }

    public void validatePresent(byte[] hash, Date atDate)
        throws ERSException, OperatorCreationException
    {
        if (timeStampToken.getTimeStampInfo().getGenTime().after(atDate))
        {
            throw new ArchiveTimeStampValidationException("timestamp generation time is in the future");
        }

        checkContainsHashValue(hash, digCalc);

        PartialHashtree[] partialTree = archiveTimeStamp.getReducedHashTree();
        byte[] rootHash;
        if (partialTree != null)
        {
            rootHash = ERSUtil.computeRootHash(digCalc, archiveTimeStamp.getReducedHashTree());
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
                return certs.iterator().next();
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

    void checkContainsHashValue(final byte[] hash, final DigestCalculator digCalc)
        throws ArchiveTimeStampValidationException
    {
        PartialHashtree[] reducedHashTree = archiveTimeStamp.getReducedHashTree();

        if (reducedHashTree != null)
        {
            for (int i = 0; i != reducedHashTree.length; i++)
            {
                PartialHashtree current = reducedHashTree[i];

                if (current.containsHash(hash))
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

    protected Date getGenTime()
        throws IOException, TSPException
    {
        final TimeStampToken timeStampToken = new TimeStampToken(archiveTimeStamp.getTimeStamp());
        return getGenTime(timeStampToken);
    }

    private Date getGenTime(final TimeStampToken timeStampToken)
    {
        return timeStampToken.getTimeStampInfo().getGenTime();
    }

    protected Date getExpiryDate()
        throws ERSException
    {
        return getExpiryDate(timeStampToken);
    }

    private Date getExpiryDate(final TimeStampToken timeStampToken)
        throws ERSException
    {
        return getSignerCertificateHolder(timeStampToken).getNotAfter();
    }

    protected X509CertificateHolder getSignerCertificateHolder(final TimeStampToken token)
        throws ArchiveTimeStampValidationException
    {
        BigInteger serialNumber = token.getSID().getSerialNumber();
        X500Name issuer = token.getSID().getIssuer();

        @SuppressWarnings("unchecked")
        Collection<X509CertificateHolder> matches = token.getCertificates()
            .getMatches(new X509CertificateHolderSelector(issuer, serialNumber));
        if (matches != null && !matches.isEmpty())
        {
            return matches.iterator().next();
        }
        else
        {
            throw new ArchiveTimeStampValidationException("no signing certificate found");
        }
    }

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
}
