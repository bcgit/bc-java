package org.bouncycastle.tsp.ers;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
    private Map<HashNode, List<ERSEvidenceRecord>> recordMap = new HashMap<HashNode, List<ERSEvidenceRecord>>();
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
                        addRecord(new HashNode(dataHashes[i]), record);
                    }
                    addRecord(new HashNode(ERSUtil.computeNodeHash(digCalc, dataLeaf)), record);
                }
                else
                {
                    addRecord(new HashNode(dataHashes[0]), record);
                }
            }
            else
            {
                // only one object - use timestamp imprint
                addRecord(new HashNode(archiveTimeStamp.getTimeStampDigestValue()), record);
            }
        }
    }

    private void addRecord(HashNode hashNode, ERSEvidenceRecord record)
    {
        List<ERSEvidenceRecord> recs = (List<ERSEvidenceRecord>)recordMap.get(hashNode);

        if (recs != null)
        {
            List<ERSEvidenceRecord> newRecs = new ArrayList<ERSEvidenceRecord>(recs.size() + 1);

            newRecs.addAll(recs);
            newRecs.add(record);

            recordMap.put(hashNode, newRecs);
        }
        else
        {
            recordMap.put(hashNode, Collections.singletonList(record));
        }
    }

    public Collection<ERSEvidenceRecord> getMatches(Selector<ERSEvidenceRecord> selector)
        throws StoreException
    {
        if (selector instanceof ERSEvidenceRecordSelector)
        {
            HashNode node = new HashNode(((ERSEvidenceRecordSelector)selector).getData().getHash(digCalc, null));
            List<ERSEvidenceRecord> records = (List<ERSEvidenceRecord>)recordMap.get(node);

            if (records != null)
            {
                List<ERSEvidenceRecord> rv = new ArrayList<ERSEvidenceRecord>(records.size());

                for (int i = 0; i != records.size(); i++)
                {
                    ERSEvidenceRecord record = (ERSEvidenceRecord)records.get(i);
                    if (selector.match(record))
                    {
                        rv.add(record);
                    }
                }

                return Collections.unmodifiableList(rv);
            }

            return Collections.unmodifiableList(new ArrayList());
        }

        if (selector == null)
        {
            // match all - use a set to avoid repeats
            Set<ERSEvidenceRecord> rv = new HashSet<ERSEvidenceRecord>(recordMap.size());
            for (Iterator it = recordMap.values().iterator(); it.hasNext(); )
            {
                rv.addAll((List<ERSEvidenceRecord>)it.next());
            }
            return Collections.unmodifiableList(new ArrayList<ERSEvidenceRecord>(rv));
        }

        Set<ERSEvidenceRecord> rv = new HashSet<ERSEvidenceRecord>();
        for (Iterator it = recordMap.values().iterator(); it.hasNext(); )
        {
            List<ERSEvidenceRecord> next = (List<ERSEvidenceRecord>)it.next();

            for (int i = 0; i != next.size(); i++)
            {
                if (selector.match(next.get(i)))
                {
                    rv.add(next.get(i));
                }
            }
        }
        
        return Collections.unmodifiableList(new ArrayList<ERSEvidenceRecord>(rv));
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
