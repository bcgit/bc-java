package org.bouncycastle.tsp.ers;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.NoSuchElementException;

/**
 * A sorting list - byte[] are sorted in ascending order.
 */
public class SortedHashList
{
    private static final Comparator<byte[]> hashComp = new ByteArrayComparator();

    private final List<byte[]> baseList = new ArrayList<byte[]>();

    private boolean isSorted = true;

    public SortedHashList()
    {
    }

    public byte[] getFirst()
    {
        if (baseList.isEmpty())
        {
            throw new NoSuchElementException();
        }

        sort();

        return (byte[])baseList.get(0);
    }

    public void add(byte[] hash)
    {
        baseList.add(hash);
        isSorted = false;
    }

    public int size()
    {
        return baseList.size();
    }

    public List<byte[]> toList()
    {
        sort();

        return new ArrayList<byte[]>(baseList);
    }

    /**
     * Sorting is deferred to the accessors. Inserting each hash on add() meant searching a
     * LinkedList for the insertion point with get(index), which is O(index), so a single add()
     * was O(n^2) and building a list of n hashes was O(n^3).
     * <p>
     * Collections.sort() is stable, so hashes comparing equal keep the order they were added
     * in - which is where inserting after the last equal element used to put them.
     */
    private void sort()
    {
        if (!isSorted)
        {
            Collections.sort(baseList, hashComp);
            isSorted = true;
        }
    }
}
