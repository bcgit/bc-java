package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsHMAC;
import org.bouncycastle.util.Arrays;

/**
 * HMAC implementation based on original internet draft for HMAC (RFC 2104).
 * <br />
 * The difference is that padding is concatenated versus XORed with the key, e.g:
 * <pre>
 *   H(K + opad, H(K + ipad, text))
 * </pre>
 *
 */
class BcSSL3HMAC
    implements TlsHMAC
{
    private static final byte IPAD_BYTE = (byte)0x36;
    private static final byte OPAD_BYTE = (byte)0x5C;

    private static final byte[] IPAD = genPad(IPAD_BYTE, 48);
    private static final byte[] OPAD = genPad(OPAD_BYTE, 48);

    private Digest digest;
    private int padLength;

    private byte[] secret;

    /**
     * Base constructor for one of the standard digest algorithms that the byteLength of
     * the algorithm is know for. Behaviour is undefined for digests other than MD5 or SHA1.
     *
     * @param digest the digest.
     */
    BcSSL3HMAC(Digest digest)
    {
        this.digest = digest;

        if (digest.getDigestSize() == 20)
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
        byte[] result = new byte[digest.getDigestSize()];
        doFinal(result, 0);
        return result;
    }

    public void calculateMAC(byte[] output, int outOff)
    {
        doFinal(output, outOff);
    }

    public int getInternalBlockSize()
    {
        return ((ExtendedDigest)digest).getByteLength();
    }

    public int getMacLength()
    {
        return digest.getDigestSize();
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

    private void doFinal(byte[] out, int outOff)
    {
        byte[] tmp = new byte[digest.getDigestSize()];
        digest.doFinal(tmp, 0);

        digest.update(secret, 0, secret.length);
        digest.update(OPAD, 0, padLength);
        digest.update(tmp, 0, tmp.length);

        digest.doFinal(out, outOff);

        reset();
    }

    private static byte[] genPad(byte b, int count)
    {
        byte[] padding = new byte[count];
        Arrays.fill(padding, b);
        return padding;
    }
}
