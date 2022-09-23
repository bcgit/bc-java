package org.bouncycastle.tsp.ers;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;

/**
 * A sorting list - byte[] are sorted in ascending order.
 */
public class SortedHashList
{
    private static final Comparator<byte[]> hashComp = new ByteArrayComparator();

    private final LinkedList<byte[]> baseList = new LinkedList<byte[]>();

    public SortedHashList()
    {
    }

    public byte[] getFirst()
    {
        return (byte[])baseList.getFirst();
    }

    public void add(byte[] hash)
    {
        if (baseList.size() == 0)
        {
             baseList.addFirst(hash);
        }
        else
        {
            if (hashComp.compare(hash, baseList.get(0)) < 0)
            {
                baseList.addFirst(hash);
            }
            else
            {
                int index = 1;
                while(index < baseList.size() && hashComp.compare(baseList.get(index), hash) <= 0)
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

    public List<byte[]> toList()
    {
        return new ArrayList<byte[]>(baseList);
    }
}
