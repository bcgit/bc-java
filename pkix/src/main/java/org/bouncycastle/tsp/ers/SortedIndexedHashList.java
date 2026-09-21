package org.bouncycastle.tsp.ers;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.NoSuchElementException;

/**
 * A sorting list - byte[] are sorted in ascending order.
 */
public class SortedIndexedHashList
{
    private static final Comparator<byte[]> hashComp = new ByteArrayComparator();

    private static final Comparator<IndexedHash> digestComp = new Comparator<IndexedHash>()
    {
        public int compare(IndexedHash l, IndexedHash r)
        {
            return hashComp.compare(l.digest, r.digest);
        }
    };

    private final List<IndexedHash> baseList = new ArrayList<IndexedHash>();

    private boolean isSorted = true;

    public SortedIndexedHashList()
    {
    }

    public IndexedHash getFirst()
    {
        if (baseList.isEmpty())
        {
            throw new NoSuchElementException();
        }

        sort();

        return (IndexedHash)baseList.get(0);
    }

    public void add(IndexedHash hash)
    {
        baseList.add(hash);
        isSorted = false;
    }

    public int size()
    {
        return baseList.size();
    }

    public List<IndexedHash> toList()
    {
        sort();

        return new ArrayList<IndexedHash>(baseList);
    }

    /**
     * Sorting is deferred to the accessors, for the reason given on SortedHashList.sort():
     * finding the insertion point with LinkedList.get(index) made building a list of n hashes
     * O(n^3). Collections.sort() is stable, so hashes comparing equal keep ascending order.
     */
    private void sort()
    {
        if (!isSorted)
        {
            Collections.sort(baseList, digestComp);
            isSorted = true;
        }
    }
}
