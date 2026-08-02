package org.bouncycastle.tsp.ers;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.tsp.ArchiveTimeStamp;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampSequence;
import org.bouncycastle.asn1.tsp.PartialHashtree;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.util.Arrays;

/**
 * Generator for RFC 4998 ArchiveTimeStamps. Data objects (and data groups) are
 * added, reduced to a single root hash via the Merkle hash tree built over their
 * PartialHashtree leaves, and a time-stamp request for that root is produced; the
 * returned time-stamp response is then turned into one or more
 * {@link ERSArchiveTimeStamp}s carrying the reduced hash tree for each object.
 */
public class ERSArchiveTimeStampGenerator
{
    private final DigestCalculator digCalc;
    private List<ERSData> dataObjects = new ArrayList<ERSData>();

    private ERSRootNodeCalculator rootNodeCalculator = new BinaryTreeRootCalculator();
    private byte[] previousChainHash;

    public ERSArchiveTimeStampGenerator(DigestCalculator digCalc)
    {
        this.digCalc = digCalc;
    }

    /**
     * Add a data object (or data group) to be covered by the archive time-stamp.
     *
     * @param dataObject the data object/group to add.
     */
    public void addData(ERSData dataObject)
    {
        dataObjects.add(dataObject);
    }

    /**
     * Add a list of data objects (or data groups) to be covered by the archive time-stamp.
     *
     * @param dataObjects the data objects/groups to add.
     */
    public void addAllData(List<ERSData> dataObjects)
    {
        this.dataObjects.addAll(dataObjects);
    }

    void addPreviousChains(ArchiveTimeStampSequence archiveTimeStampSequence)
        throws IOException
    {
        OutputStream digOut = digCalc.getOutputStream();

        digOut.write(archiveTimeStampSequence.getEncoded(ASN1Encoding.DER));
        digOut.close();

        this.previousChainHash = digCalc.getDigest();
    }

    /**
     * Generate a time-stamp request for the root hash of the Merkle tree built over
     * the data objects added so far.
     *
     * @param tspReqGenerator generator to use for building the request.
     * @return a time-stamp request over the computed root hash.
     * @throws TSPException on a time-stamp processing error.
     * @throws IOException on an encoding error.
     */
    public TimeStampRequest generateTimeStampRequest(TimeStampRequestGenerator tspReqGenerator)
        throws TSPException, IOException
    {
        IndexedPartialHashtree[] reducedHashTree = getPartialHashtrees();

        byte[] rootHash = rootNodeCalculator.computeRootHash(digCalc, reducedHashTree);

        return tspReqGenerator.generate(digCalc.getAlgorithmIdentifier(), rootHash);
    }

    /**
     * Generate a time-stamp request for the root hash with the passed in nonce.
     *
     * @param tspReqGenerator generator to use for building the request.
     * @param nonce nonce to include in the request.
     * @return a time-stamp request over the computed root hash.
     * @throws TSPException on a time-stamp processing error.
     * @throws IOException on an encoding error.
     */
    public TimeStampRequest generateTimeStampRequest(TimeStampRequestGenerator tspReqGenerator, BigInteger nonce)
        throws TSPException, IOException
    {
        IndexedPartialHashtree[] reducedHashTree = getPartialHashtrees();

        byte[] rootHash = rootNodeCalculator.computeRootHash(digCalc, reducedHashTree);

        return tspReqGenerator.generate(digCalc.getAlgorithmIdentifier(), rootHash, nonce);
    }

    /**
     * Generate a single ArchiveTimeStamp from the passed in time-stamp response.
     * The response's imprint must match the algorithm and root hash of the data
     * added; this form requires exactly one data object (one reduced hash tree).
     *
     * @param tspResponse the response carrying the time-stamp over the root hash.
     * @return the ArchiveTimeStamp covering the added data.
     * @throws TSPException if the response has an error status or its imprint does not match.
     * @throws ERSException if more than one reduced hash tree is present, or on a processing error.
     */
    public ERSArchiveTimeStamp generateArchiveTimeStamp(TimeStampResponse tspResponse)
        throws TSPException, ERSException
    {
        IndexedPartialHashtree[] reducedHashTree = getPartialHashtrees();
        if (reducedHashTree.length != 1)
        {
            throw new ERSException("multiple reduced hash trees found");
        }

        byte[] rootHash = rootNodeCalculator.computeRootHash(digCalc, reducedHashTree);

        if (tspResponse.getStatus() != 0)
        {
            throw new TSPException("TSP response error status: " + tspResponse.getStatusString());
        }

        TSTInfo tstInfo = tspResponse.getTimeStampToken().getTimeStampInfo().toASN1Structure();

        // the imprint algorithm comes from the TSA, which may name the digest with NULL parameters
        // where we name it with them absent - RFC 5754 sec. 2 requires both to be accepted
        if (!AlgorithmIdentifier.areEquivalent(tstInfo.getMessageImprint().getHashAlgorithm(),
            digCalc.getAlgorithmIdentifier()))
        {
            throw new ERSException("time stamp imprint for wrong algorithm");
        }

        if (!Arrays.areEqual(tstInfo.getMessageImprint().getHashedMessage(), rootHash))
        {
            throw new ERSException("time stamp imprint for wrong root hash");
        }

        if (reducedHashTree[0].getValueCount() == 1)
        {
            // just include the TimeStamp
            return new ERSArchiveTimeStamp(new ArchiveTimeStamp(null, null,
                tspResponse.getTimeStampToken().toCMSSignedData().toASN1Structure()), digCalc);
        }
        else
        {
            return new ERSArchiveTimeStamp(new ArchiveTimeStamp(digCalc.getAlgorithmIdentifier(), reducedHashTree,
                tspResponse.getTimeStampToken().toCMSSignedData().toASN1Structure()), digCalc);
        }
    }

    /**
     * Generate one ArchiveTimeStamp per added data object from the passed in
     * time-stamp response, each carrying the reduced hash tree (the sibling path
     * through the Merkle tree) needed to recover the time-stamped root for that object.
     *
     * @param tspResponse the response carrying the time-stamp over the root hash.
     * @return a list of ArchiveTimeStamps, one per data object, in the order the data was added.
     * @throws TSPException if the response has an error status or its imprint does not match.
     * @throws ERSException on a processing error.
     */
    public List<ERSArchiveTimeStamp> generateArchiveTimeStamps(TimeStampResponse tspResponse)
        throws TSPException, ERSException
    {
        IndexedPartialHashtree[] reducedHashTree = getPartialHashtrees();

        byte[] rootHash = rootNodeCalculator.computeRootHash(digCalc, reducedHashTree);

        if (tspResponse.getStatus() != 0)
        {
            throw new TSPException("TSP response error status: " + tspResponse.getStatusString());
        }

        TSTInfo tstInfo = tspResponse.getTimeStampToken().getTimeStampInfo().toASN1Structure();

        // the imprint algorithm comes from the TSA, which may name the digest with NULL parameters
        // where we name it with them absent - RFC 5754 sec. 2 requires both to be accepted
        if (!AlgorithmIdentifier.areEquivalent(tstInfo.getMessageImprint().getHashAlgorithm(),
            digCalc.getAlgorithmIdentifier()))
        {
            throw new ERSException("time stamp imprint for wrong algorithm");
        }

        if (!Arrays.areEqual(tstInfo.getMessageImprint().getHashedMessage(), rootHash))
        {
            throw new ERSException("time stamp imprint for wrong root hash");
        }

        ContentInfo timeStamp = tspResponse.getTimeStampToken().toCMSSignedData().toASN1Structure();
        List<ERSArchiveTimeStamp> atss = new ArrayList<ERSArchiveTimeStamp>();

        if (reducedHashTree.length == 1 && reducedHashTree[0].getValueCount() == 1)
        {
            // just include the TimeStamp
            atss.add(new ERSArchiveTimeStamp(new ArchiveTimeStamp(null, null, timeStamp), digCalc));
        }
        else
        {
            ERSArchiveTimeStamp[] archiveTimeStamps = new ERSArchiveTimeStamp[reducedHashTree.length];

            // we compute the final hash tree by left first traversal.
            for (int i = 0; i != reducedHashTree.length; i++)
            {
                PartialHashtree[] path = rootNodeCalculator.computePathToRoot(digCalc, reducedHashTree[i], i);

                archiveTimeStamps[reducedHashTree[i].order] = new ERSArchiveTimeStamp(new ArchiveTimeStamp(digCalc.getAlgorithmIdentifier(), path, timeStamp), digCalc);
            }

            // fix the ordering
            for (int i = 0; i != reducedHashTree.length; i++)
            {
                atss.add(archiveTimeStamps[i]);
            }
        }

        return atss;
    }

    private IndexedPartialHashtree[] getPartialHashtrees()
    {
        List<IndexedHash> hashes = ERSUtil.buildIndexedHashList(digCalc, dataObjects, previousChainHash);
        IndexedPartialHashtree[] trees = new IndexedPartialHashtree[hashes.size()];

        Set<ERSDataGroup> dataGroupSet = new HashSet<ERSDataGroup>();
        for (int i = 0; i != dataObjects.size(); i++)
        {
            if (dataObjects.get(i) instanceof ERSDataGroup)
            {
                dataGroupSet.add((ERSDataGroup)dataObjects.get(i));
            }
        }

        // replace groups
        for (int i = 0; i != hashes.size(); i++)
        {
            byte[] hash = ((IndexedHash)hashes.get(i)).digest;
            ERSData d = (ERSData)dataObjects.get(((IndexedHash)hashes.get(i)).order);

            if (d instanceof ERSDataGroup)
            {
                ERSDataGroup data = (ERSDataGroup)d;

                List<byte[]> dHashes = data.getHashes(digCalc, previousChainHash);
                trees[i] = new IndexedPartialHashtree(((IndexedHash)hashes.get(i)).order, (byte[][])dHashes.toArray(new byte[dHashes.size()][]));
            }
            else
            {
                trees[i] = new IndexedPartialHashtree(((IndexedHash)hashes.get(i)).order, hash);
            }
        }

        return trees;
    }

    private static class IndexedPartialHashtree
        extends PartialHashtree
    {
        final int order;

        private IndexedPartialHashtree(int order, byte[] partial)
        {
            super(partial);
            this.order = order;
        }

        private IndexedPartialHashtree(int order, byte[][] partial)
        {
            super(partial);
            this.order = order;
        }
    }
}
