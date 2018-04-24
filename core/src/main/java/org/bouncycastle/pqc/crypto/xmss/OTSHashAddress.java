package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.util.Pack;

/**
 * OTS hash address.
 */
final class OTSHashAddress
    extends XMSSAddress
{

    private static final int TYPE = 0x00;

    private final int otsAddress;
    private final int chainAddress;
    private final int hashAddress;

    private OTSHashAddress(Builder builder)
    {
        super(builder);
        otsAddress = builder.otsAddress;
        chainAddress = builder.chainAddress;
        hashAddress = builder.hashAddress;
    }

    protected static class Builder
        extends XMSSAddress.Builder<Builder>
    {

        /* optional */
        private int otsAddress = 0;
        private int chainAddress = 0;
        private int hashAddress = 0;

        protected Builder()
        {
            super(TYPE);
        }

        protected Builder withOTSAddress(int val)
        {
            otsAddress = val;
            return this;
        }

        protected Builder withChainAddress(int val)
        {
            chainAddress = val;
            return this;
        }

        protected Builder withHashAddress(int val)
        {
            hashAddress = val;
            return this;
        }

        @Override
        protected XMSSAddress build()
        {
            return new OTSHashAddress(this);
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
        Pack.intToBigEndian(otsAddress, byteRepresentation,16);
        Pack.intToBigEndian(chainAddress, byteRepresentation, 20);
        Pack.intToBigEndian(hashAddress, byteRepresentation, 24);
        return byteRepresentation;
    }

    protected int getOTSAddress()
    {
        return otsAddress;
    }

    protected int getChainAddress()
    {
        return chainAddress;
    }

    protected int getHashAddress()
    {
        return hashAddress;
    }
}
