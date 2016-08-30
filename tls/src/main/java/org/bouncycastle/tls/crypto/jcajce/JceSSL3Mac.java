package org.bouncycastle.tls.crypto.jcajce;

import java.io.IOException;
import java.security.MessageDigest;

import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsMac;
import org.bouncycastle.util.Arrays;

/**
 * A generic TLS SSl3 MAC implementation.
 */
public class JceSSL3Mac
    implements TlsMac
{
    protected TlsContext context;
    protected byte[] secret;
    protected SSL3Mac mac;
    protected int digestBlockSize;
    protected int digestOverhead;
    protected int macLength;

    /**
     * Generate a new instance of an TlsMac.
     *
     * @param context the TLS client context
     * @param digest  The digest to use.
     */
    public JceSSL3Mac(TlsContext context, MessageDigest digest)
    {
        this.context = context;

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

        this.mac = new SSL3Mac(digest);

        // TODO This should check the actual algorithm, not assume based on the digest size
        if (digest.getDigestLength() == 20)
        {
            /*
             * NOTE: When SHA-1 is used with the SSL 3.0 MAC, the secret + input pad is not
             * digest block-aligned.
             */
            this.digestOverhead = 4;
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

        byte[] result = new byte[mac.getMacSize()];
        mac.doFinal(result, 0);
        return truncate(result);
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

    public void setKey(byte[] macKey)
        throws IOException
    {
        this.secret = Arrays.clone(macKey);

        this.mac.init(secret);

        this.macLength = mac.getMacSize();
        if (context.getSecurityParameters().isTruncatedHMac())
        {
            this.macLength = Math.min(this.macLength, 10);
        }
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

    /**
     * HMAC implementation based on original internet draft for HMAC (RFC 2104)
     * <p>
     * The difference is that padding is concatenated versus XORed with the key
     * <p>
     * H(K + opad, H(K + ipad, text))
     */
    private static class SSL3Mac
    {
        private static final byte IPAD_BYTE = (byte)0x36;
        private static final byte OPAD_BYTE = (byte)0x5C;

        private static final byte[] IPAD = genPad(IPAD_BYTE, 48);
        private static final byte[] OPAD = genPad(OPAD_BYTE, 48);

        private MessageDigest digest;
        private int padLength;

        private byte[] secret;

        /**
         * Base constructor for one of the standard digest algorithms that the byteLength of
         * the algorithm is know for. Behaviour is undefined for digests other than MD5 or SHA1.
         *
         * @param digest the digest.
         */
        public SSL3Mac(MessageDigest digest)
        {
            this.digest = digest;

            if (digest.getDigestLength() == 20)
            {
                this.padLength = 40;
            }
            else
            {
                this.padLength = 48;
            }
        }

        public void init(byte[] secret)
        {
            this.secret = secret;

            reset();
        }

        public int getMacSize()
        {
            return digest.getDigestLength();
        }

        public void update(byte in)
        {
            digest.update(in);
        }

        public void update(byte[] in, int inOff, int len)
        {
            digest.update(in, inOff, len);
        }

        public int doFinal(byte[] out, int outOff)
        {
            byte[] tmp = digest.digest();

            digest.update(secret, 0, secret.length);
            digest.update(OPAD, 0, padLength);
            digest.update(tmp, 0, tmp.length);

            System.arraycopy(digest.digest(), 0, out, outOff, digest.getDigestLength());

            reset();

            return digest.getDigestLength();
        }

        /**
         * Reset the mac generator.
         */
        public void reset()
        {
            digest.reset();
            digest.update(secret, 0, secret.length);
            digest.update(IPAD, 0, padLength);
        }

        private static byte[] genPad(byte b, int count)
        {
            byte[] padding = new byte[count];
            Arrays.fill(padding, b);
            return padding;
        }
    }
}
