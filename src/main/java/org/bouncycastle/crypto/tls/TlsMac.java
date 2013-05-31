package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.LongDigest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

/**
 * A generic TLS MAC implementation, acting as an HMAC based on some underlying Digest.
 */
public class TlsMac
{

    protected TlsContext context;
    protected byte[] secret;
    protected Mac mac;
    protected int digestBlockSize;
    protected int digestOverhead;

    /**
     * Generate a new instance of an TlsMac.
     *
     * @param context the TLS client context
     * @param digest  The digest to use.
     * @param key     A byte-array where the key for this mac is located.
     * @param keyOff  The number of bytes to skip, before the key starts in the buffer.
     * @param len     The length of the key.
     */
    public TlsMac(TlsContext context, Digest digest, byte[] key, int keyOff, int keyLen)
    {
        this.context = context;

        KeyParameter keyParameter = new KeyParameter(key, keyOff, keyLen);

        this.secret = Arrays.clone(keyParameter.getKey());

        // TODO This should check the actual algorithm, not rely on the engine type
        if (digest instanceof LongDigest)
        {
            this.digestBlockSize = 128;
            this.digestOverhead = 16;
        }
        else
        {
            this.digestBlockSize = 64;
            this.digestOverhead = 8;
        }

        if (context.getServerVersion().isSSL())
        {
            this.mac = new SSL3Mac(digest);

            // TODO This should check the actual algorithm, not assume based on the digest size
            if (digest.getDigestSize() == 20)
            {
                /*
                 * NOTE: When SHA-1 is used with the SSL 3.0 MAC, the secret + input pad is not
                 * digest block-aligned.
                 */
                this.digestOverhead = 4;
            }
        }
        else
        {
            this.mac = new HMac(digest);

            // NOTE: The input pad for HMAC is always a full digest block
        }

        this.mac.init(keyParameter);
    }

    /**
     * @return the MAC write secret
     */
    public byte[] getMACSecret()
    {
        return this.secret;
    }

    /**
     * @return The Keysize of the mac.
     */
    public int getSize()
    {
        return mac.getMacSize();
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

        ProtocolVersion serverVersion = context.getServerVersion();
        boolean isSSL = serverVersion.isSSL();

        ByteArrayOutputStream bosMac = new ByteArrayOutputStream(isSSL ? 11 : 13);
        try
        {
            TlsUtils.writeUint64(seqNo, bosMac);
            TlsUtils.writeUint8(type, bosMac);

            if (!isSSL)
            {
                TlsUtils.writeVersion(serverVersion, bosMac);
            }

            TlsUtils.writeUint16(length, bosMac);
        }
        catch (IOException e)
        {
            // This should never happen
            throw new IllegalStateException("Internal error during mac calculation");
        }

        byte[] macHeader = bosMac.toByteArray();
        mac.update(macHeader, 0, macHeader.length);
        mac.update(message, offset, length);

        byte[] result = new byte[mac.getMacSize()];
        mac.doFinal(result, 0);
        return result;
    }

    public byte[] calculateMacConstantTime(long seqNo, short type, byte[] message, int offset, int length,
                                           int fullLength, byte[] dummyData)
    {

        /*
         * Actual MAC only calculated on 'length' bytes...
         */
        byte[] result = calculateMac(seqNo, type, message, offset, length);

        /*
         * ...but ensure a constant number of complete digest blocks are processed (as many as would
         * be needed for 'fullLength' bytes of input).
         */
        int headerLength = context.getServerVersion().isSSL() ? 11 : 13;

        // How many extra full blocks do we need to calculate?
        int extra = getDigestBlockCount(headerLength + fullLength) - getDigestBlockCount(headerLength + length);

        while (--extra >= 0)
        {
            mac.update(dummyData, 0, digestBlockSize);
        }

        // One more byte in case the implementation is "lazy" about processing blocks
        mac.update(dummyData[0]);
        mac.reset();

        return result;
    }

    private int getDigestBlockCount(int inputLength)
    {
        // NOTE: This calculation assumes a minimum of 1 pad byte
        return (inputLength + digestOverhead) / digestBlockSize;
    }
}
