package org.bouncycastle.tsp.ers;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.bouncycastle.asn1.tsp.ArchiveTimeStamp;
import org.bouncycastle.asn1.tsp.PartialHashtree;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;

public class ERSEvidenceRecordStore
    implements Store<ERSEvidenceRecord>
{
    private Map<HashNode, ERSEvidenceRecord> recordMap = new HashMap<HashNode, ERSEvidenceRecord>();
    private DigestCalculator digCalc = null;

    public ERSEvidenceRecordStore(Collection<ERSEvidenceRecord> records)
        throws OperatorCreationException
    {

        for (Iterator it = records.iterator(); it.hasNext(); )
        {
            ERSEvidenceRecord record = (ERSEvidenceRecord)it.next();
            ArchiveTimeStamp archiveTimeStamp = record.getArchiveTimeStamps()[0];

            if (digCalc == null)
            {
                DigestCalculatorProvider digProv = record.getDigestAlgorithmProvider();
                digCalc = digProv.get(archiveTimeStamp.getDigestAlgorithmIdentifier());
            }

            PartialHashtree dataLeaf = archiveTimeStamp.getHashTreeLeaf();

            if (dataLeaf != null)
            {
                byte[][] dataHashes = dataLeaf.getValues();

                if (dataHashes.length > 1)
                {
                    // a data group
                    for (int i = 0; i != dataHashes.length; i++)
                    {
                        recordMap.put(new HashNode(dataHashes[i]), record);
                    }
                    recordMap.put(new HashNode(ERSUtil.computeNodeHash(digCalc, dataLeaf)), record);
                }
                else
                {
                    recordMap.put(new HashNode(dataHashes[0]), record);
                }
            }
            else
            {
                // only one object - use timestamp imprint
                recordMap.put(new HashNode(archiveTimeStamp.getTimeStampDigestValue()), record);
            }
        }
    }

    public Collection<ERSEvidenceRecord> getMatches(Selector<ERSEvidenceRecord> selector)
        throws StoreException
    {
        if (selector instanceof ERSEvidenceRecordSelector)
        {
            // TODO: more than one evidence record might contain the same data
            HashNode node = new HashNode(((ERSEvidenceRecordSelector)selector).getData().getHash(digCalc));
            ERSEvidenceRecord record = recordMap.get(node);

            if (record != null)
            {
                return Collections.singletonList(record);
            }
        }

        return Collections.EMPTY_LIST;
    }

    private static class HashNode
    {
        private final byte[] dataHash;
        private final int hashCode;

        public HashNode(byte[] dataHash)
        {
            this.dataHash = dataHash;
            this.hashCode = Arrays.hashCode(dataHash);
        }

        public int hashCode()
        {
            return hashCode;
        }

        public boolean equals(Object o)
        {
            if (o instanceof HashNode)
            {
                return Arrays.areEqual(dataHash, ((HashNode)o).dataHash);
            }

            return false;
        }
    }
}
