package org.bouncycastle.tls.crypto.jcajce;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.util.Arrays;

/**
 * A generic TLS MAC implementation, acting as an HMAC based on some underlying Digest.
 */
public class JceTlsMac
{
    protected TlsContext context;
    protected byte[] secret;
    protected Mac mac;
    protected int digestBlockSize;
    protected int digestOverhead;
    protected int macLength;

    /**
     * Generate a new instance of an TlsMac.
     *
     * @param context the TLS client context
     * @param digest  The digest to use.
     * @param key     A byte-array where the key for this MAC is located.
     * @param keyOff  The number of bytes to skip, before the key starts in the buffer.
     * @param keyLen  The length of the key.
     */
    public JceTlsMac(TlsContext context, MessageDigest digest, byte[] key, int keyOff, int keyLen)
        throws GeneralSecurityException
    {
        this.context = context;

        SecretKey keyParameter = new SecretKeySpec(key, keyOff, keyLen, "Hmac" + digest.getAlgorithm());

        this.secret = Arrays.clone(keyParameter.getEncoded());

        // TODO This should check the actual algorithm, not rely on the engine type
        if (digest.getAlgorithm().endsWith("384") || digest.getAlgorithm().contains("512"))
        {
            this.digestBlockSize = 128;
            this.digestOverhead = 16;
        }
        else
        {
            this.digestBlockSize = 64;
            this.digestOverhead = 8;
        }

        if (TlsUtils.isSSL(context))
        {
            throw new UnsupportedOperationException("SSL v3 not supported");
        }
        else
        {
            this.mac = ((JcaTlsCrypto)context.getCrypto()).getHelper().createMac("Hmac" + digest.getAlgorithm());

            // NOTE: The input pad for HMAC is always a full digest block
        }

        this.mac.init(keyParameter);

        this.macLength = mac.getMacLength();
        if (context.getSecurityParameters().isTruncatedHMac())
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
        ProtocolVersion serverVersion = context.getServerVersion();
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

        return truncate(mac.doFinal());
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
        int headerLength = TlsUtils.isSSL(context) ? 11 : 13;

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
