package org.bouncycastle.tls.crypto.impl.jcajce;

import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsHMAC;
import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.util.Arrays;

/**
 * HMAC implementation based on original internet draft for HMAC (RFC 2104)
 * <p/>
 * The difference is that padding is concatenated versus XORed with the key
 * <p/>
 * H(K + opad, H(K + ipad, text))
 */
class JcaSSL3HMAC
    implements TlsHMAC
{
    private static final byte IPAD_BYTE = (byte)0x36;
    private static final byte OPAD_BYTE = (byte)0x5C;

    private static final byte[] IPAD = genPad(IPAD_BYTE, 48);
    private static final byte[] OPAD = genPad(OPAD_BYTE, 48);

    private TlsHash digest;
    private final int digestSize;
    private final int internalBlockSize;
    private int padLength;

    private byte[] secret;

    /**
     * Base constructor for one of the standard digest algorithms for which the byteLength of
     * the algorithm is known. Behaviour is undefined for digests other than MD5 or SHA1.
     *
     * @param digest            the digest.
     * @param digestSize        the digest size.
     * @param internalBlockSize the digest internal block size.
     */
    JcaSSL3HMAC(TlsHash digest, int digestSize, int internalBlockSize)
    {
        this.digest = digest;
        this.digestSize = digestSize;
        this.internalBlockSize = internalBlockSize;

        if (digestSize == 20)
        {
            this.padLength = 40;
        }
        else
        {
            this.padLength = 48;
        }
    }

    public void setKey(byte[] key, int keyOff, int keyLen)
    {
        this.secret = TlsUtils.copyOfRangeExact(key, keyOff, keyOff + keyLen);

        reset();
    }

    public void update(byte[] in, int inOff, int len)
    {
        digest.update(in, inOff, len);
    }

    public byte[] calculateMAC()
    {
        byte[] tmp = digest.calculateHash();

        digest.update(secret, 0, secret.length);
        digest.update(OPAD, 0, padLength);
        digest.update(tmp, 0, tmp.length);

        byte[] result = digest.calculateHash();
        reset();
        return result;
    }

    public void calculateMAC(byte[] output, int outOff)
    {
        byte[] result = calculateMAC();
        System.arraycopy(result, 0, output, outOff, result.length);
    }

    public int getInternalBlockSize()
    {
        return internalBlockSize;
    }

    public int getMacLength()
    {
        return digestSize;
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
