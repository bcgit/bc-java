package org.bouncycastle.pqc.crypto.xmss;

import java.io.Serializable;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

import org.bouncycastle.util.Integers;

public class BDSStateMap
    implements Serializable
{
    private final Map<Integer, BDS> bdsState = new TreeMap<Integer, BDS>();

    BDSStateMap()
    {

    }

    void setXMSS(XMSSParameters xmss)
    {
        for (Iterator it = bdsState.keySet().iterator(); it.hasNext();)
        {
            Integer key = (Integer)it.next();

            BDS bds = bdsState.get(key);
            bds.setXMSS(xmss);
            bds.validate();
        }
    }

    void update()
    {
        for (Iterator it = bdsState.keySet().iterator(); it.hasNext();)
        {
            Integer key = (Integer)it.next();

            BDS bds = bdsState.get(key);
            if (bds.isUsed())
            {
                bdsState.put(key, bds.getNextState());
            }
        }
    }

    public boolean isEmpty()
    {
        return bdsState.isEmpty();
    }

    public BDS get(int index)
    {
        return bdsState.get(Integers.valueOf(index));
    }

    public void put(int index, BDS bds)
    {
        bdsState.put(Integers.valueOf(index), bds);
    }
}
