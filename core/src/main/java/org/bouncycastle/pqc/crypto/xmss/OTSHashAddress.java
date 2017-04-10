package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;

import org.bouncycastle.util.Pack;

/**
 * OTS Hash address.
 *
 */
public class OTSHashAddress
    extends XMSSAddress
{

    private static final int TYPE = 0x00;
    private int otsAddress;
    private int chainAddress;
    private int hashAddress;

    public OTSHashAddress()
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
        otsAddress = Pack.bigEndianToInt(address, 16);
        chainAddress = Pack.bigEndianToInt(address, 20);
        hashAddress = Pack.bigEndianToInt(address, 24);
        super.parseByteArray(address);
    }

    @Override
    public byte[] toByteArray()
    {
        byte[] byteRepresentation = getByteRepresentation();
        XMSSUtil.intToBytesBigEndianOffset(byteRepresentation, otsAddress, 16);
        XMSSUtil.intToBytesBigEndianOffset(byteRepresentation, chainAddress, 20);
        XMSSUtil.intToBytesBigEndianOffset(byteRepresentation, hashAddress, 24);
        return super.toByteArray();
    }

    public int getOTSAddress()
    {
        return otsAddress;
    }

    public void setOTSAddress(int otsAddress)
    {
        this.otsAddress = otsAddress;
    }

    public int getChainAddress()
    {
        return chainAddress;
    }

    public void setChainAddress(int chainAddress)
    {
        this.chainAddress = chainAddress;
    }

    public int getHashAddress()
    {
        return hashAddress;
    }

    public void setHashAddress(int hashAddress)
    {
        this.hashAddress = hashAddress;
    }
}
