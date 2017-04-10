package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;

import org.bouncycastle.util.Pack;

/**
 * XMSS Address.
 *
 */
public abstract class XMSSAddress
{

    private int layerAddress;
    private long treeAddress;
    private int type;
    private int keyAndMask;
    private byte[] byteRepresentation;

    protected XMSSAddress(int type)
    {
        this.type = type;
        byteRepresentation = new byte[32];
    }

    protected void parseByteArray(byte[] address)
        throws ParseException
    {
        if (address.length != 32)
        {
            throw new IllegalArgumentException("address needs to be 32 byte");
        }
        layerAddress = Pack.bigEndianToInt(address, 0);
        treeAddress = Pack.bigEndianToLong(address, 4);
        keyAndMask = Pack.bigEndianToInt(address, 28);
    }

    public byte[] toByteArray()
    {
        XMSSUtil.intToBytesBigEndianOffset(byteRepresentation, layerAddress, 0);
        XMSSUtil.longToBytesBigEndianOffset(byteRepresentation, treeAddress, 4);
        XMSSUtil.intToBytesBigEndianOffset(byteRepresentation, type, 12);
        XMSSUtil.intToBytesBigEndianOffset(byteRepresentation, keyAndMask, 28);
        return byteRepresentation;
    }

    public int getLayerAddress()
    {
        return layerAddress;
    }

    public void setLayerAddress(int layerAddress)
    {
        this.layerAddress = layerAddress;
    }

    public long getTreeAddress()
    {
        return treeAddress;
    }

    public void setTreeAddress(long treeAddress)
    {
        this.treeAddress = treeAddress;
    }

    public int getType()
    {
        return type;
    }

    protected void setType(int type)
    {
        this.type = type;
    }

    public long getKeyAndMask()
    {
        return keyAndMask;
    }

    public void setKeyAndMask(int keyAndMask)
    {
        this.keyAndMask = keyAndMask;
    }

    protected byte[] getByteRepresentation()
    {
        return byteRepresentation;
    }
}
