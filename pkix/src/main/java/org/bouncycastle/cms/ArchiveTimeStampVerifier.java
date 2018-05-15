package org.bouncycastle.cms;

import org.bouncycastle.asn1.cms.ArchiveTimeStamp;
import org.bouncycastle.asn1.cms.DataGroup;
import org.bouncycastle.asn1.cms.PartialHashtree;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.selector.X509CertificateHolderSelector;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.ByteArrayComparator;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Date;
import java.util.SortedSet;
import java.util.TreeSet;

public class ArchiveTimeStampVerifier
{
    private ArchiveTimeStamp archiveTimeStamp;
    private PartialHashTreeVerifier partialHashTreeVerifier = new PartialHashTreeVerifier();

    public void validate(final Object data, final Date prevGenTime, final Date prevExpTime,
        final AlgorithmIdentifier
        algId)
        throws ArchiveTimeStampValidationException,
        NoSuchAlgorithmException,
        IOException,
        TSPException,
        PartialHashTreeVerificationException, CertificateException, OperatorCreationException {
        final MessageDigest messageDigest = MessageDigest.getInstance(algId.getAlgorithm().getId());
        final TimeStampToken timeStampToken = new TimeStampToken(archiveTimeStamp.getTimeStamp());
        containsObjectHashValue(data, messageDigest);
        checkAlgorithmConsistent(algId);
        checkGenTimeValid(timeStampToken, prevGenTime, prevExpTime);
        final byte[] rootHash = getRootHash(messageDigest);
        if (rootHash != null) {
            checkTimeStampValid(timeStampToken, getRootHash(messageDigest));
        }
        checkTimeStampTokenValid(timeStampToken);
    }

    /**
     * Verify that the Archive Timestamp contains the hash value of the provided object
     * @param data
     * @throws NoSuchAlgorithmException
     */
    public void containsObjectHashValue(final Object data, final MessageDigest messageDigest)
        throws PartialHashTreeVerificationException, NoSuchAlgorithmException {

        if (data instanceof byte[])
        {
            containsHashValue((byte[]) data, messageDigest);
        }
        else if (data instanceof DataGroup)
        {
            containsDataGroupHashValue((DataGroup) data, messageDigest);
        }
        else
        {
            throw new IllegalArgumentException("unknown object in containsHashValue: " + data.getClass()
                .getName());
        }
    }

    public void containsHashValue(final byte[] data, final MessageDigest messageDigest)
        throws PartialHashTreeVerificationException
    {
        final ASN1TaggedObject reducedHashTree = archiveTimeStamp.getReducedHashTree();
        if (reducedHashTree != null) {
            ASN1Sequence partialHashTrees = ASN1Sequence
                .getInstance(reducedHashTree.getObject());
            PartialHashtree current = PartialHashtree
                .getInstance(partialHashTrees.getObjectAt(0));

            PartialHashTreeVerifier verifier = new PartialHashTreeVerifier();
            verifier.checkContainsHash(current, messageDigest.digest(data));
        }
    }

    public void containsDataGroupHashValue(final byte[] hash)
        throws PartialHashTreeVerificationException {

        final ASN1TaggedObject reducedHashTree = archiveTimeStamp.getReducedHashTree();

        ASN1Sequence partialHashTrees = ASN1Sequence
            .getInstance(reducedHashTree.getObject());
        PartialHashtree current = PartialHashtree
            .getInstance(partialHashTrees.getObjectAt(0));

        PartialHashTreeVerifier verifier = new PartialHashTreeVerifier();
        verifier.checkContainsHash(current, hash);
    }

    public void containsDataGroupHashValue(final DataGroup data, final MessageDigest messageDigest)
        throws PartialHashTreeVerificationException {
        if (data.getHashes(messageDigest).size() == 1)
        {
            containsDataGroupHashValue(data.getHash(messageDigest));
        }
        else
        {
            containsObjectsHashValues(data.getHashes(messageDigest));
        }
    }

    public void containsObjectsHashValues(final Collection<byte[]> data)
        throws PartialHashTreeVerificationException {
        final ASN1TaggedObject reducedHashTree = archiveTimeStamp.getReducedHashTree();
        final ASN1Sequence partialHashTrees = ASN1Sequence.getInstance(reducedHashTree.getObject());
        final PartialHashtree current = PartialHashtree.getInstance(partialHashTrees.getObjectAt
            (0));

        for (final byte[] hash : data)
        {
            partialHashTreeVerifier.checkContainsHash(current, hash);
        }
    }

    public void checkAlgorithmConsistent(final AlgorithmIdentifier algorithmIdentifier) throws
            ArchiveTimeStampValidationException
    {
        if (! archiveTimeStamp.getAlgorithmIdentifier().getAlgorithm().equals
            (algorithmIdentifier.getAlgorithm()))
        {
            throw new ArchiveTimeStampValidationException("digest algorithm is not consistent "
                + "with other archive timestamps in chain");
        }
    }

    public void checkTimeStampValid(final TimeStampToken timeStampToken, final byte[] hash)
        throws ArchiveTimeStampValidationException
    {
        if (hash != null) {
            if (!ByteUtils
                .equals(hash, timeStampToken.getTimeStampInfo().getMessageImprintDigest())) {
                throw new ArchiveTimeStampValidationException("timestamp's message imprint digest "
                    + "does not match object hash");
            }
        }
    }

    public void checkGenTimeValid(final TimeStampToken timeStampToken, final Date prevGenTime,
        final Date prevExpTime)
        throws ArchiveTimeStampValidationException
    {
        final Date genTime = timeStampToken.getTimeStampInfo().getGenTime();

        if (! genTime.after(prevGenTime) || ! genTime.before(prevExpTime))
        {
            throw new ArchiveTimeStampValidationException("timestamp's generation time is not "
                + "consistent with previous timestamp");
        }
    }

    public byte[] getRootHash(final MessageDigest messageDigest)
    {
        byte[] root = null;
        ASN1TaggedObject reducedHashTree = archiveTimeStamp.getReducedHashTree();

        if (reducedHashTree != null)
        {
            ASN1Sequence partialHashtrees = ASN1Sequence.getInstance(
                reducedHashTree.getObject());

            if (partialHashtrees.size() == 1) {
                final PartialHashtree pht = PartialHashtree.getInstance(partialHashtrees.getObjectAt
                    (0));
                return partialHashTreeVerifier.getHash(pht, messageDigest);
            }

            for (int i = 0; i < partialHashtrees.size(); i++) {
                final PartialHashtree currentNode = PartialHashtree.getInstance(partialHashtrees
                    .getObjectAt(i));
                byte[] currentHash = partialHashTreeVerifier.getHash(currentNode, messageDigest);
                final SortedSet<byte[]> hashes = new TreeSet<>(new ByteArrayComparator());

                hashes.add(currentHash);
                if (root == null) {
                    root = currentHash;
                } else {
                    hashes.add(root);
                    final byte[] concat = ByteUtils.concatenate(hashes.first(), hashes.last());
                    root = messageDigest.digest(concat);
                }
            }
            return root;
        }
        return null;
    }

    protected Date getGenTime() throws IOException, TSPException
    {
        final TimeStampToken timeStampToken = new TimeStampToken(archiveTimeStamp.getTimeStamp());
        return getGenTime(timeStampToken);
    }

    private Date getGenTime(final TimeStampToken timeStampToken) {
        return timeStampToken.getTimeStampInfo().getGenTime();
    }

    protected Date getExpiryDate()
        throws IOException, TSPException, ArchiveTimeStampValidationException
    {
        final TimeStampToken timeStampToken = new TimeStampToken(archiveTimeStamp.getTimeStamp());
        return getExpiryDate(timeStampToken);
    }

    private Date getExpiryDate(final TimeStampToken timeStampToken)
        throws ArchiveTimeStampValidationException
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
        if (matches != null && ! matches.isEmpty())
        {
            return matches.iterator().next();
        }
        else
        {
            throw new ArchiveTimeStampValidationException("no signing certificate found");
        }

    }

    public void setArchiveTimeStamp(ArchiveTimeStamp archiveTimeStamp) {
        this.archiveTimeStamp = archiveTimeStamp;
    }

    private void checkTimeStampTokenValid(TimeStampToken timeStampToken)
        throws TSPException, CertificateException, ArchiveTimeStampValidationException, OperatorCreationException {

        X509CertificateHolder signerCertificateHolder = getSignerCertificateHolder(timeStampToken);
        SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder()
            .build(signerCertificateHolder);
        timeStampToken.validate(verifier);
    }
}
