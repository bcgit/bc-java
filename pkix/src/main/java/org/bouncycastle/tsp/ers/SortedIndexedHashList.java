package org.bouncycastle.tsp.ers;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;

/**
 * A sorting list - byte[] are sorted in ascending order.
 */
public class SortedIndexedHashList
{
    private static final Comparator<byte[]> hashComp = new ByteArrayComparator();

    private final LinkedList<IndexedHash> baseList = new LinkedList<IndexedHash>();

    public SortedIndexedHashList()
    {
    }

    public IndexedHash getFirst()
    {
        return (IndexedHash)baseList.getFirst();
    }

    public void add(IndexedHash hash)
    {
        if (baseList.size() == 0)
        {
             baseList.addFirst(hash);
        }
        else
        {
            if (hashComp.compare(hash.digest, ((IndexedHash)baseList.get(0)).digest) < 0)
            {
                baseList.addFirst(hash);
            }
            else
            {
                int index = 1;
                while(index < baseList.size() && hashComp.compare(((IndexedHash)baseList.get(index)).digest, hash.digest) <= 0)
                {
                    index++;
                }

                if (index == baseList.size())
                {
                    baseList.add(hash);
                }
                else
                {
                    baseList.add(index, hash);
                }
            }
        }
    }

    public int size()
    {
        return baseList.size();
    }

    public List<IndexedHash> toList()
    {
        return new ArrayList<IndexedHash>(baseList);
    }
}
