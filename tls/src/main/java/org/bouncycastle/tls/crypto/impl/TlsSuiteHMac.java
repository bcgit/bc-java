package org.bouncycastle.tls.crypto.impl;

import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsHMAC;
import org.bouncycastle.tls.crypto.TlsMAC;
import org.bouncycastle.util.Arrays;

/**
 * A generic TLS MAC implementation, acting as an HMAC based on some underlying Digest.
 */
class TlsSuiteHMac
    implements TlsSuiteMac
{
    static int getMacSize(TlsCryptoParameters cryptoParams, TlsMAC mac)
    {
        int macSize = mac.getMacLength();
        if (cryptoParams.getSecurityParametersHandshake().isTruncatedHMac())
        {
            macSize = Math.min(macSize, 10);
        }
        return macSize;
    }

    protected final TlsCryptoParameters cryptoParams;
    protected final TlsHMAC mac;
    protected final int digestBlockSize;
    protected final int digestOverhead;
    protected final int macSize;

    /**
     * Generate a new instance of an TlsMac.
     *
     * @param cryptoParams the TLS client context specific crypto parameters.
     * @param mac  The MAC to use.
     */
    public TlsSuiteHMac(TlsCryptoParameters cryptoParams, TlsHMAC mac)
    {
        this.cryptoParams = cryptoParams;
        this.mac = mac;
        this.macSize = getMacSize(cryptoParams, mac);
        this.digestBlockSize = mac.getInternalBlockSize();

        // TODO This should check the actual algorithm, not assume based on the digest size
        if (TlsImplUtils.isSSL(cryptoParams) && mac.getMacLength() == 20)
        {
            /*
             * NOTE: For the SSL 3.0 MAC with SHA-1, the secret + input pad is not block-aligned.
             */
            this.digestOverhead = 4;
        }
        else
        {
            this.digestOverhead = digestBlockSize / 8;
        }
    }

    /**
     * @return The output length of this MAC.
     */
    public int getSize()
    {
        return macSize;
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
        ProtocolVersion serverVersion = cryptoParams.getServerVersion();
        boolean isSSL = serverVersion.isSSL();

        byte[] macHeader = new byte[isSSL ? 11 : 13];
        TlsUtils.writeUint64(seqNo, macHeader, 0);
        TlsUtils.writeUint8(type, macHeader, 8);
        if (!isSSL)
        {
            TlsUtils.writeVersion(serverVersion, macHeader, 9);
        }
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
        int headerLength = TlsImplUtils.isSSL(cryptoParams) ? 11 : 13;

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
        // NOTE: The input pad for HMAC is always a full digest block

        // NOTE: This calculation assumes a minimum of 1 pad byte
        return (inputLength + digestOverhead) / digestBlockSize;
    }

    protected byte[] truncate(byte[] bs)
    {
        if (bs.length <= macSize)
        {
            return bs;
        }

        return Arrays.copyOf(bs, macSize);
    }
}
