package org.bouncycastle.pqc.crypto.sphincsplus;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

class ADRS
{
    public static final int WOTS_HASH = 0;
    public static final int WOTS_PK = 1;
    public static final int TREE = 2;
    public static final int FORS_TREE = 3;
    public static final int FORS_PK = 4;
    public static final int WOTS_PRF = 5;
    public static final int FORS_PRF = 6;
    
    static final int OFFSET_LAYER = 0;
    static final int OFFSET_TREE = 4;
    static final int OFFSET_TREE_HGT = 24;
    static final int OFFSET_TREE_INDEX = 28;
    static final int OFFSET_TYPE = 16;
    static final int OFFSET_KP_ADDR = 20;
    static final int OFFSET_CHAIN_ADDR = 24;
    static final int OFFSET_HASH_ADDR = 28;
    
    final byte[] value = new byte[32];

    ADRS()
    {
    }

    ADRS(ADRS adrs)
    {
        System.arraycopy(adrs.value, 0, this.value, 0, adrs.value.length);
    }

    public void setLayerAddress(int layer)
    {
        Pack.intToBigEndian(layer, value, OFFSET_LAYER);
    }

    public int getLayerAddress()
    {
        return Pack.bigEndianToInt(value, OFFSET_LAYER);
    }

    public void setTreeAddress(long tree)
    {
        // tree address is 12 bytes
        Pack.longToBigEndian(tree, value, OFFSET_TREE + 4);
    }

    public long getTreeAddress()
    {
        return Pack.bigEndianToLong(value, OFFSET_TREE + 4);
    }

    public void setTreeHeight(int height)
    {
        Pack.intToBigEndian(height, value, OFFSET_TREE_HGT);
    }

    public int getTreeHeight()
    {
        return Pack.bigEndianToInt(value, OFFSET_TREE_HGT);
    }

    public void setTreeIndex(int index)
    {
        Pack.intToBigEndian(index, value, OFFSET_TREE_INDEX);
    }

    public int getTreeIndex()
    {
        return Pack.bigEndianToInt(value, OFFSET_TREE_INDEX);
    }

    // resets part of value to zero in line with 2.7.3
    public void setType(int type)
    {
        Pack.intToBigEndian(type, value, OFFSET_TYPE);

        Arrays.fill(value, 20, value.length, (byte)0);
    }

    public void changeType(int type)
    {
        Pack.intToBigEndian(type, value, OFFSET_TYPE);
    }

    public int getType()
    {
        return Pack.bigEndianToInt(value, OFFSET_TYPE);
    }

    public void setKeyPairAddress(int keyPairAddr)
    {
        Pack.intToBigEndian(keyPairAddr, value, OFFSET_KP_ADDR);
    }

    public int getKeyPairAddress()
    {
        return Pack.bigEndianToInt(value, OFFSET_KP_ADDR);
    }

    public void setHashAddress(int hashAddr)
    {
        Pack.intToBigEndian(hashAddr, value, OFFSET_HASH_ADDR);
    }          

    public void setChainAddress(int chainAddr)
    {
        Pack.intToBigEndian(chainAddr, value, OFFSET_CHAIN_ADDR);
    }
}
