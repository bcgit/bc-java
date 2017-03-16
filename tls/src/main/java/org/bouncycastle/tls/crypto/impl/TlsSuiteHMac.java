package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;

import org.bouncycastle.tls.ProtocolVersion;
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
    protected byte[] secret;
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

        if (TlsImplUtils.isSSL(cryptoParams))
        {
            // TODO This should check the actual algorithm, not assume based on the digest size
            if (mac.getMacLength() == 20)
            {
                /*
                 * NOTE: When SHA-1 is used with the SSL 3.0 MAC, the secret + input pad is not
                 * digest block-aligned.
                 */
                this.digestOverhead = 4;
            }
        }

        // NOTE: The input pad for HMAC is always a full digest block
        this.mac = mac;
    }

    public void setKey(byte[] key)
        throws IOException
    {
        this.secret = Arrays.clone(key);

        this.mac.setKey(secret);

        this.macLength = mac.getMacLength();
        if (cryptoParams.getSecurityParameters().isTruncatedHMac())
        {
            this.macLength = Math.min(this.macLength, 10);
        }
    }

    /**
     * @return the MAC write secret
     */
    public byte[] getMACSecret()
    {
        return this.secret;
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
     * @param message A byte-buffer containing the message.
     * @param offset  The number of bytes to skip, before the message starts.
     * @param length  The length of the message.
     * @return A new byte-buffer containing the MAC value.
     */
    public byte[] calculateMac(long seqNo, short type, byte[] message, int offset, int length)
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
        TlsUtils.writeUint16(length, macHeader, macHeader.length - 2);

        mac.update(macHeader, 0, macHeader.length);
        mac.update(message, offset, length);

        return truncate(mac.calculateMAC());
    }

    public byte[] calculateMacConstantTime(long seqNo, short type, byte[] message, int offset, int length,
                                           int expectedLength, byte[] dummyData)
    {
        /*
         * Actual MAC only calculated on 'length' bytes...
         */
        byte[] result = calculateMac(seqNo, type, message, offset, length);

        /*
         * ...but ensure a constant number of complete digest blocks are processed (as many as would
         * be needed for 'fullLength' bytes of input).
         */
        int headerLength = TlsImplUtils.isSSL(cryptoParams) ? 11 : 13;

        // How many extra full blocks do we need to calculate?
        int extra = getDigestBlockCount(headerLength + expectedLength) - getDigestBlockCount(headerLength + length);

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
