package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;

import org.bouncycastle.util.Pack;

/**
 * XMSS L-tree address.
 *
 */
public class LTreeAddress
    extends XMSSAddress
{

    private static final int TYPE = 0x01;
    private int lTreeAddress;
    private int treeHeight;
    private int treeIndex;

    public LTreeAddress()
    {
        super(TYPE);
    }

    @Override
    public void parseByteArray(byte[] address)
        throws ParseException
    {
        int type = Pack.bigEndianToInt(address, 12);
        if (type != TYPE)
        {
            throw new ParseException("type needs to be " + TYPE, 12);
        }
        setType(type);
        lTreeAddress = Pack.bigEndianToInt(address, 16);
        treeHeight = Pack.bigEndianToInt(address, 20);
        treeIndex = Pack.bigEndianToInt(address, 24);
        super.parseByteArray(address);
    }

    @Override
    public byte[] toByteArray()
    {
        byte[] byteRepresentation = getByteRepresentation();
        XMSSUtil.intToBytesBigEndianOffset(byteRepresentation, lTreeAddress, 16);
        XMSSUtil.intToBytesBigEndianOffset(byteRepresentation, treeHeight, 20);
        XMSSUtil.intToBytesBigEndianOffset(byteRepresentation, treeIndex, 24);
        return super.toByteArray();
    }

    public int getLTreeAddress()
    {
        return lTreeAddress;
    }

    public void setLTreeAddress(int lTreeAddress)
    {
        this.lTreeAddress = lTreeAddress;
    }

    public int getTreeHeight()
    {
        return treeHeight;
    }

    public void setTreeHeight(int treeHeight)
    {
        this.treeHeight = treeHeight;
    }

    public int getTreeIndex()
    {
        return treeIndex;
    }

    public void setTreeIndex(int treeIndex)
    {
        this.treeIndex = treeIndex;
    }
}
