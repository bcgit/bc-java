package org.bouncycastle.tsp.ers;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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
 * Generator for RFC 4998 Archive Time Stamps.
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

    public void addData(ERSData dataObject)
    {
        dataObjects.add(dataObject);
    }

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

    public TimeStampRequest generateTimeStampRequest(TimeStampRequestGenerator tspReqGenerator)
        throws TSPException, IOException
    {
        IndexedPartialHashtree[] reducedHashTree = getPartialHashtrees();

        byte[] rootHash = rootNodeCalculator.computeRootHash(digCalc, reducedHashTree);

        return tspReqGenerator.generate(digCalc.getAlgorithmIdentifier(), rootHash);
    }

    public TimeStampRequest generateTimeStampRequest(TimeStampRequestGenerator tspReqGenerator, BigInteger nonce)
        throws TSPException, IOException
    {
        IndexedPartialHashtree[] reducedHashTree = getPartialHashtrees();

        byte[] rootHash = rootNodeCalculator.computeRootHash(digCalc, reducedHashTree);

        return tspReqGenerator.generate(digCalc.getAlgorithmIdentifier(), rootHash, nonce);
    }

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

        if (!tstInfo.getMessageImprint().getHashAlgorithm().equals(digCalc.getAlgorithmIdentifier()))
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

        if (!tstInfo.getMessageImprint().getHashAlgorithm().equals(digCalc.getAlgorithmIdentifier()))
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
