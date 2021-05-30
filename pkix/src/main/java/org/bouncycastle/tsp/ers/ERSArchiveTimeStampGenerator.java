package org.bouncycastle.tsp.ers;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.tsp.ArchiveTimeStamp;
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

    public TimeStampRequest generateTimeStampRequest(TimeStampRequestGenerator tspReqGenerator)
        throws TSPException, IOException
    {
        PartialHashtree[] reducedHashTree = getPartialHashtrees();

        byte[] rootHash = rootNodeCalculator.computeRootHash(digCalc, reducedHashTree);

        return tspReqGenerator.generate(digCalc.getAlgorithmIdentifier(), rootHash);
    }

    public TimeStampRequest generateTimeStampRequest(TimeStampRequestGenerator tspReqGenerator, BigInteger nonce)
        throws TSPException, IOException
    {
        PartialHashtree[] reducedHashTree = getPartialHashtrees();

        byte[] rootHash = rootNodeCalculator.computeRootHash(digCalc, reducedHashTree);

        return tspReqGenerator.generate(digCalc.getAlgorithmIdentifier(), rootHash, nonce);
    }

    public ERSArchiveTimeStamp generateArchiveTimeStamp(TimeStampResponse tspResponse)
        throws TSPException, ERSException
    {
        PartialHashtree[] reducedHashTree = getPartialHashtrees();

        byte[] rootHash = rootNodeCalculator.computeRootHash(digCalc, reducedHashTree);

        TSTInfo tstInfo = tspResponse.getTimeStampToken().getTimeStampInfo().toASN1Structure();

        if (!tstInfo.getMessageImprint().getHashAlgorithm().equals(digCalc.getAlgorithmIdentifier()))
        {
            throw new ERSException("time stamp imprint for wrong algorithm");
        }

        if (!Arrays.areEqual(tstInfo.getMessageImprint().getHashedMessage(), rootHash))
        {
            throw new ERSException("time stamp imprint for wrong root hash");
        }

        ArchiveTimeStamp ats;
        if (reducedHashTree.length == 1)
        {
            // just include the TimeStamp
            ats = new ArchiveTimeStamp(null, null,
                tspResponse.getTimeStampToken().toCMSSignedData().toASN1Structure());
        }
        else
        {
            ats = new ArchiveTimeStamp(digCalc.getAlgorithmIdentifier(), reducedHashTree,
                tspResponse.getTimeStampToken().toCMSSignedData().toASN1Structure());
        }

        return new ERSArchiveTimeStamp(ats, digCalc, rootNodeCalculator);
    }

    private PartialHashtree[] getPartialHashtrees()
    {
        List<byte[]> hashes = ERSUtil.buildHashList(digCalc, dataObjects);
        PartialHashtree[] trees = new PartialHashtree[hashes.size()];

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
            byte[] hash = (byte[])hashes.get(i);
            ERSDataGroup found = null;

            for (Iterator it = dataGroupSet.iterator(); it.hasNext();)
            {
                ERSDataGroup data = (ERSDataGroup)it.next();

                byte[] dHash = data.getHash(digCalc);
                if (Arrays.areEqual(dHash, hash))
                {
                    List<byte[]> dHashes = data.getHashes(digCalc);
                    trees[i] = new PartialHashtree((byte[][])dHashes.toArray(new byte[dHashes.size()][]));
                    found = data;
                    break;
                }
            }
            if (found == null)
            {
                trees[i] = new PartialHashtree(hash);
            }
            else
            {
                dataGroupSet.remove(found);
            }
        }

        return trees;
    }
}
