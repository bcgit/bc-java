package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.util.Pack;

/**
 * Hash tree address.
 */
final class HashTreeAddress
    extends XMSSAddress
{

    private static final int TYPE = 0x02;
    private static final int PADDING = 0x00;

    private final int padding;
    private final int treeHeight;
    private final int treeIndex;

    private HashTreeAddress(Builder builder)
    {
        super(builder);
        padding = PADDING;
        treeHeight = builder.treeHeight;
        treeIndex = builder.treeIndex;
    }

    protected static class Builder
        extends XMSSAddress.Builder<Builder>
    {

        /* optional */
        private int treeHeight = 0;
        private int treeIndex = 0;

        protected Builder()
        {
            super(TYPE);
        }

        protected Builder withTreeHeight(int val)
        {
            treeHeight = val;
            return this;
        }

        protected Builder withTreeIndex(int val)
        {
            treeIndex = val;
            return this;
        }

        @Override
        protected XMSSAddress build()
        {
            return new HashTreeAddress(this);
        }

        @Override
        protected Builder getThis()
        {
            return this;
        }
    }

    @Override
    protected byte[] toByteArray()
    {
        byte[] byteRepresentation = super.toByteArray();
        Pack.intToBigEndian(padding, byteRepresentation,16);
        Pack.intToBigEndian(treeHeight, byteRepresentation, 20);
        Pack.intToBigEndian(treeIndex, byteRepresentation, 24);
        return byteRepresentation;
    }

    protected int getPadding()
    {
        return padding;
    }

    protected int getTreeHeight()
    {
        return treeHeight;
    }

    protected int getTreeIndex()
    {
        return treeIndex;
    }
}
