package org.bouncycastle.kmip.wire;

import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

public class KMIPStructure
    implements KMIPItem
{
    private final int tag;
    private final KMIPItem[] items;

    public KMIPStructure(int tag, KMIPItem item)
    {
        this.tag = tag;
        this.items = new KMIPItem[] { item };
    }

    public KMIPStructure(int tag, KMIPItem[] items)
    {
        this.tag = tag;
        this.items = new KMIPItem[items.length];
        System.arraycopy(items, 0, this.items, 0, items.length);
    }

    public KMIPStructure(int tag, List<KMIPItem> items)
    {
        this.tag = tag;
        this.items = (KMIPItem[])items.toArray(new KMIPItem[items.size()]);
    }

    public int getTag()
    {
        return tag;
    }

    public byte getType()
    {
        return KMIPType.STRUCTURE;
    }

    public long getLength()
    {
        long totalLength = 0;

        for (int i = 0; i != items.length; i++)
        {
            KMIPItem item = items[i];
            long length = item.getLength();

            totalLength += 8; // the header

            // the body
            if (length <= 8)
            {
                totalLength += 8;
            }
            else
            {
                if (length % 8 == 0)
                {
                    totalLength += length;
                }
                else
                {
                    totalLength += ((length / 8) + 1) * 8;
                }
            }
        }

        return totalLength;
    }

    public List<KMIPItem> getValue()
    {
        return Collections.unmodifiableList(Arrays.asList(items));
    }

    public KMIPItem toKMIPItem()
    {
        return this;
    }
}
