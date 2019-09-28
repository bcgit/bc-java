package org.bouncycastle.pqc.crypto.xmss;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.util.Integers;

public class BDSStateMap
    implements Serializable
{
    private static final long serialVersionUID = -3464451825208522308L;
    
    private final Map<Integer, BDS> bdsState = new TreeMap<Integer, BDS>();

    private transient long maxIndex;

    BDSStateMap(long maxIndex)
    {
        this.maxIndex = maxIndex;
    }

    BDSStateMap(BDSStateMap stateMap, long maxIndex)
    {
        for (Iterator it = stateMap.bdsState.keySet().iterator(); it.hasNext();)
        {
            Integer key = (Integer)it.next();

            bdsState.put(key, new BDS(stateMap.bdsState.get(key)));
        }
        this.maxIndex = maxIndex;
    }

    BDSStateMap(XMSSMTParameters params, long globalIndex, byte[] publicSeed, byte[] secretKeySeed)
    {
        this.maxIndex = (1L << params.getHeight()) - 1;
        for (long index = 0; index < globalIndex; index++)
        {
            updateState(params, index, publicSeed, secretKeySeed);
        }
    }

    public long getMaxIndex()
    {
        return maxIndex;
    }

    void updateState(XMSSMTParameters params, long globalIndex, byte[] publicSeed, byte[] secretKeySeed)
    {
        XMSSParameters xmssParams = params.getXMSSParameters();
        int xmssHeight = xmssParams.getHeight();

        //
        // set up state for next signature
        //
        long indexTree = XMSSUtil.getTreeIndex(globalIndex, xmssHeight);
        int indexLeaf = XMSSUtil.getLeafIndex(globalIndex, xmssHeight);

        OTSHashAddress otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withTreeAddress(indexTree)
            .withOTSAddress(indexLeaf).build();

        /* prepare authentication path for next leaf */
        if (indexLeaf < ((1 << xmssHeight) - 1))
        {
            if (this.get(0) == null || indexLeaf == 0)
            {
                this.put(0, new BDS(xmssParams, publicSeed, secretKeySeed, otsHashAddress));
            }

            this.update(0, publicSeed, secretKeySeed, otsHashAddress);
        }

        /* loop over remaining layers */
        for (int layer = 1; layer < params.getLayers(); layer++)
        {
                /* get root of layer - 1 */
            indexLeaf = XMSSUtil.getLeafIndex(indexTree, xmssHeight);
            indexTree = XMSSUtil.getTreeIndex(indexTree, xmssHeight);
                /* adjust addresses */
            otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withLayerAddress(layer)
                .withTreeAddress(indexTree).withOTSAddress(indexLeaf).build();

                /* prepare authentication path for next leaf */
            if (bdsState.get(layer) == null || XMSSUtil.isNewBDSInitNeeded(globalIndex, xmssHeight, layer))
            {
                bdsState.put(layer, new BDS(xmssParams, publicSeed, secretKeySeed, otsHashAddress));
            }

            if (indexLeaf < ((1 << xmssHeight) - 1)
                && XMSSUtil.isNewAuthenticationPathNeeded(globalIndex, xmssHeight, layer))
            {
                this.update(layer, publicSeed, secretKeySeed, otsHashAddress);
            }
        }
    }

    public boolean isEmpty()
    {
        return bdsState.isEmpty();
    }

    BDS get(int index)
    {
        return bdsState.get(Integers.valueOf(index));
    }

    BDS update(int index, byte[] publicSeed, byte[] secretKeySeed, OTSHashAddress otsHashAddress)
    {
        return bdsState.put(Integers.valueOf(index), bdsState.get(Integers.valueOf(index)).getNextState(publicSeed, secretKeySeed, otsHashAddress));
    }

    void put(int index, BDS bds)
    {
        bdsState.put(Integers.valueOf(index), bds);
    }

    public BDSStateMap withWOTSDigest(ASN1ObjectIdentifier digestName)
    {
        BDSStateMap newStateMap = new BDSStateMap(this.maxIndex);

        for (Iterator<Integer> keys = bdsState.keySet().iterator(); keys.hasNext();)
        {
            Integer key = keys.next();

            newStateMap.bdsState.put(key, bdsState.get(key).withWOTSDigest(digestName));
        }
        
        return newStateMap;
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        if (in.available() != 0)
        {
            this.maxIndex = in.readLong();
        }
        else
        {
            this.maxIndex = 0;
        }
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeLong(this.maxIndex);
    }
}
