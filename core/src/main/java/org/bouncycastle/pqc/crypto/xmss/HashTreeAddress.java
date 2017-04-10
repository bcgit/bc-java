package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;

import org.bouncycastle.util.Pack;

/**
 * XMSS Hash Tree address.
 *
 */
public class HashTreeAddress
    extends XMSSAddress
{

    private static final int TYPE = 0x02;
    private static final int PADDING = 0x00;

    private int padding;
    private int treeHeight;
    private int treeIndex;

    public HashTreeAddress()
    {
        super(TYPE);
        padding = PADDING;
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
        int padding = Pack.bigEndianToInt(address, 16);
        if (padding != PADDING)
        {
            throw new ParseException("padding needs to be " + PADDING, 16);
        }
        treeHeight = Pack.bigEndianToInt(address, 20);
        treeIndex = Pack.bigEndianToInt(address, 24);
        super.parseByteArray(address);
    }

    @Override
    public byte[] toByteArray()
    {
        byte[] byteRepresentation = getByteRepresentation();
        XMSSUtil.intToBytesBigEndianOffset(byteRepresentation, padding, 16);
        XMSSUtil.intToBytesBigEndianOffset(byteRepresentation, treeHeight, 20);
        XMSSUtil.intToBytesBigEndianOffset(byteRepresentation, treeIndex, 24);
        return super.toByteArray();
    }

    public int getPadding()
    {
        return padding;
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
