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

    public BDSStateMap(BDSStateMap stateMap)
    {
        for (Iterator it = stateMap.bdsState.keySet().iterator(); it.hasNext();)
        {
            Integer key = (Integer)it.next();

            bdsState.put(key, stateMap.bdsState.get(key));
        }
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

    public boolean isEmpty()
    {
        return bdsState.isEmpty();
    }

    public BDS get(int index)
    {
        return bdsState.get(Integers.valueOf(index));
    }

    public BDS update(int index, byte[] publicSeed, byte[] secretKeySeed, OTSHashAddress otsHashAddress)
    {
        return bdsState.put(Integers.valueOf(index), bdsState.get(Integers.valueOf(index)).getNextState(publicSeed, secretKeySeed, otsHashAddress));
    }

    public void put(int index, BDS bds)
    {
        bdsState.put(Integers.valueOf(index), bds);
    }
}
