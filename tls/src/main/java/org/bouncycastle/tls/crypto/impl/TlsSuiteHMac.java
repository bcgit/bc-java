package org.bouncycastle.tls.crypto.impl;

import org.bouncycastle.tls.ContentType;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsHMAC;
import org.bouncycastle.tls.crypto.TlsMAC;
import org.bouncycastle.util.Arrays;

/**
 * A generic TLS MAC implementation, acting as an HMAC based on some underlying Digest.
 */
public final class TlsSuiteHMac
    implements TlsSuiteMac
{
    private static final long SEQUENCE_NUMBER_PLACEHOLDER = -1L;

    private static int getMacSize(TlsCryptoParameters cryptoParams, TlsMAC mac)
    {
        int macSize = mac.getMacLength();
        if (cryptoParams.getSecurityParametersHandshake().isTruncatedHMac())
        {
            macSize = Math.min(macSize, 10);
        }
        return macSize;
    }

    private final TlsCryptoParameters cryptoParams;
    private final TlsHMAC mac;
    private final int digestBlockSize;
    private final int digestOverhead;
    private final int macSize;
    
    /**
     * Generate a new instance of a TlsMac.
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

    public int getSize()
    {
        return macSize;
    }

    public byte[] calculateMac(long seqNo, short type, byte[] connectionID, byte[] msg, int msgOff, int msgLen)
    {
        ProtocolVersion serverVersion = cryptoParams.getServerVersion();

        if (!Arrays.isNullOrEmpty(connectionID))
        {
            int cidLength = connectionID.length;
            byte[] macHeader = new byte[23 + cidLength];
            TlsUtils.writeUint64(SEQUENCE_NUMBER_PLACEHOLDER, macHeader, 0);
            TlsUtils.writeUint8(ContentType.tls12_cid, macHeader, 8);
            TlsUtils.writeUint8(cidLength, macHeader, 9);
            TlsUtils.writeUint8(ContentType.tls12_cid, macHeader, 10);
            TlsUtils.writeVersion(serverVersion, macHeader, 11);
            TlsUtils.writeUint64(seqNo, macHeader, 13);
            System.arraycopy(connectionID, 0, macHeader, 21, cidLength);
            TlsUtils.writeUint16(msgLen, macHeader, 21 + cidLength);

            mac.update(macHeader, 0, macHeader.length);
        }
        else
        {
            byte[] macHeader = new byte[13];
            TlsUtils.writeUint64(seqNo, macHeader, 0);
            TlsUtils.writeUint8(type, macHeader, 8);
            TlsUtils.writeVersion(serverVersion, macHeader, 9);
            TlsUtils.writeUint16(msgLen, macHeader, 11);

            mac.update(macHeader, 0, macHeader.length);
        }

        mac.update(msg, msgOff, msgLen);

        return truncate(mac.calculateMAC());
    }

    public byte[] calculateMacConstantTime(long seqNo, short type, byte[] connectionID, byte[] msg, int msgOff,
        int msgLen, int fullLength, byte[] dummyData)
    {
        /*
         * Actual MAC only calculated on 'length' bytes...
         */
        byte[] result = calculateMac(seqNo, type, connectionID, msg, msgOff, msgLen);

        /*
         * ...but ensure a constant number of complete digest blocks are processed (as many as would
         * be needed for 'fullLength' bytes of input).
         */
        int headerLength = getHeaderLength(connectionID);

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

    private int getDigestBlockCount(int inputLength)
    {
        // NOTE: The input pad for HMAC is always a full digest block

        // NOTE: This calculation assumes a minimum of 1 pad byte
        return (inputLength + digestOverhead) / digestBlockSize;
    }

    private int getHeaderLength(byte[] connectionID)
    {
        if (TlsImplUtils.isSSL(cryptoParams))
        {
            return 11;
        }
        else if (!Arrays.isNullOrEmpty(connectionID))
        {
            return 23 + connectionID.length;
        }
        else
        {
            return 13;
        }
    }

    private byte[] truncate(byte[] bs)
    {
        if (bs.length <= macSize)
        {
            return bs;
        }

        return Arrays.copyOf(bs, macSize);
    }
}
