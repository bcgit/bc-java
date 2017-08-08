package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;

import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsHMAC;
import org.bouncycastle.util.Arrays;

/**
 * A generic TLS MAC implementation, acting as an HMAC based on some underlying Digest.
 */
class TlsSuiteHMac
    implements TlsSuiteMac
{
    protected TlsCryptoParameters cryptoParams;
    protected TlsHMAC mac;
    protected int digestBlockSize;
    protected int digestOverhead;
    protected int macLength;

    /**
     * Generate a new instance of an TlsMac.
     *
     * @param cryptoParams the TLS client context specific crypto parameters.
     * @param mac  The MAC to use.
     */
    public TlsSuiteHMac(TlsCryptoParameters cryptoParams, TlsHMAC mac)
    {
        this.cryptoParams = cryptoParams;

        this.digestBlockSize = mac.getInternalBlockSize();
        this.digestOverhead = digestBlockSize / 8;

        // NOTE: The input pad for HMAC is always a full digest block
        this.mac = mac;
    }

    public void setKey(byte[] key) throws IOException
    {
        this.mac.setKey(key);

        this.macLength = mac.getMacLength();
        if (cryptoParams.getSecurityParameters().isTruncatedHMac())
        {
            this.macLength = Math.min(this.macLength, 10);
        }
    }

    /**
     * @return The output length of this MAC.
     */
    public int getSize()
    {
        return macLength;
    }

    /**
     * Calculate the MAC for some given data.
     *
     * @param type    The message type of the message.
     * @param msg     A byte-buffer containing the message.
     * @param msgOff  The number of bytes to skip, before the message starts.
     * @param msgLen  The length of the message.
     * @return A new byte-buffer containing the MAC value.
     */
    public byte[] calculateMac(long seqNo, short type, byte[] msg, int msgOff, int msgLen)
    {
        byte[] macHeader = new byte[13];
        TlsUtils.writeUint64(seqNo, macHeader, 0);
        TlsUtils.writeUint8(type, macHeader, 8);
        TlsUtils.writeVersion(cryptoParams.getServerVersion(), macHeader, 9);
        TlsUtils.writeUint16(msgLen, macHeader, macHeader.length - 2);

        mac.update(macHeader, 0, macHeader.length);
        mac.update(msg, msgOff, msgLen);

        return truncate(mac.calculateMAC());
    }

    public byte[] calculateMacConstantTime(long seqNo, short type, byte[] msg, int msgOff, int msgLen,
        int fullLength, byte[] dummyData)
    {
        /*
         * Actual MAC only calculated on 'length' bytes...
         */
        byte[] result = calculateMac(seqNo, type, msg, msgOff, msgLen);

        /*
         * ...but ensure a constant number of complete digest blocks are processed (as many as would
         * be needed for 'fullLength' bytes of input).
         */
        int headerLength = 13;

        // How many extra full blocks do we need to calculate?
        int extra = getDigestBlockCount(headerLength + fullLength) - getDigestBlockCount(headerLength + msgLen);

        while (--extra >= 0)
        {
            mac.update(dummyData, 0, digestBlockSize);
        }

        // One more byte in case the implementation is "lazy" about processing blocks
        mac.update(dummyData, 0, 1);
        mac.reset();

        return result;
    }

    protected int getDigestBlockCount(int inputLength)
    {
        // NOTE: This calculation assumes a minimum of 1 pad byte
        return (inputLength + digestOverhead) / digestBlockSize;
    }

    protected byte[] truncate(byte[] bs)
    {
        if (bs.length <= macLength)
        {
            return bs;
        }

        return Arrays.copyOf(bs, macLength);
    }
}
