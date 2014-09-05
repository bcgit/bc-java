package org.bouncycastle.crypto.signers;

import java.math.BigInteger;
import java.util.Hashtable;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.SignerWithRecovery;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.encoders.Hex;

/**
 * X9.31-1998 - signing using a hash.
 * <p>
 * The message digest hash, H, is encapsulated to form a byte string as follows
 * <pre>
 * EB = 06 || PS || 0xBA || H || TRAILER
 * </pre>
 * where PS is a string of bytes all of value 0xBB of length such that |EB|=|n|, and TRAILER is the ISO/IEC 10118 part number† for the digest. The byte string, EB, is converted to an integer value, the message representative, f.
 */
public class X931Signer
    implements Signer
{
    static final public int   TRAILER_IMPLICIT    = 0xBC;
    static final public int   TRAILER_RIPEMD160   = 0x31CC;
    static final public int   TRAILER_RIPEMD128   = 0x32CC;
    static final public int   TRAILER_SHA1        = 0x33CC;
    static final public int   TRAILER_SHA256      = 0x34CC;
    static final public int   TRAILER_SHA512      = 0x35CC;
    static final public int   TRAILER_SHA384      = 0x36CC;
    static final public int   TRAILER_WHIRLPOOL   = 0x37CC;

    private static Hashtable  trailerMap          = new Hashtable();

    static
    {
        trailerMap.put("RIPEMD128", Integers.valueOf(TRAILER_RIPEMD128));
        trailerMap.put("RIPEMD160", Integers.valueOf(TRAILER_RIPEMD160));

        trailerMap.put("SHA-1", Integers.valueOf(TRAILER_SHA1));
        trailerMap.put("SHA-256", Integers.valueOf(TRAILER_SHA256));
        trailerMap.put("SHA-384", Integers.valueOf(TRAILER_SHA384));
        trailerMap.put("SHA-512", Integers.valueOf(TRAILER_SHA512));

        trailerMap.put("Whirlpool", Integers.valueOf(TRAILER_WHIRLPOOL));
    }

    private Digest                      digest;
    private AsymmetricBlockCipher       cipher;
    private RSAKeyParameters            kParam;

    private int         trailer;
    private int         keyBits;
    private byte[]      block;

    /**
     * Generate a signer for the with either implicit or explicit trailers
     * for ISO9796-2.
     *
     * @param cipher base cipher to use for signature creation/verification
     * @param digest digest to use.
     * @param implicit whether or not the trailer is implicit or gives the hash.
     */
    public X931Signer(
        AsymmetricBlockCipher cipher,
        Digest digest,
        boolean implicit)
    {
        this.cipher = cipher;
        this.digest = digest;

        if (implicit)
        {
            trailer = TRAILER_IMPLICIT;
        }
        else
        {
            Integer trailerObj = (Integer)trailerMap.get(digest.getAlgorithmName());

            if (trailerObj != null)
            {
                trailer = trailerObj.intValue();
            }
            else
            {
                throw new IllegalArgumentException("no valid trailer for digest");
            }
        }
    }

    /**
     * Constructor for a signer with an explicit digest trailer.
     *
     * @param cipher cipher to use.
     * @param digest digest to sign with.
     */
    public X931Signer(
        AsymmetricBlockCipher cipher,
        Digest digest)
    {
        this(cipher, digest, false);
    }
    
    public void init(
        boolean                 forSigning,
        CipherParameters        param)
    {
        kParam = (RSAKeyParameters)param;

        cipher.init(forSigning, kParam);

        keyBits = kParam.getModulus().bitLength();

        block = new byte[(keyBits + 7) / 8];

        reset();
    }
    
    /**
     * clear possible sensitive data
     */
    private void clearBlock(
        byte[]  block)
    {
        for (int i = 0; i != block.length; i++)
        {
            block[i] = 0;
        }
    }

    /**
     * update the internal digest with the byte b
     */
    public void update(
        byte    b)
    {
        digest.update(b);
    }

    /**
     * update the internal digest with the byte array in
     */
    public void update(
        byte[]  in,
        int     off,
        int     len)
    {
        digest.update(in, off, len);
    }

    /**
     * reset the internal state
     */
    public void reset()
    {
        digest.reset();
    }

    /**
     * generate a signature for the loaded message using the key we were
     * initialised with.
     */
    public byte[] generateSignature()
        throws CryptoException
    {
        createSignatureBlock();

        BigInteger t = new BigInteger(cipher.processBlock(block, 0, block.length));
        BigInteger nSubT = kParam.getModulus().subtract(t);

        clearBlock(block);

        if (t.compareTo(nSubT) > 0)
        {
            return BigIntegers.asUnsignedByteArray((kParam.getModulus().bitLength() + 7) / 8, nSubT);
        }
        else
        {
            return BigIntegers.asUnsignedByteArray((kParam.getModulus().bitLength() + 7) / 8, t);
        }
    }

    private void createSignatureBlock()
    {
        int     digSize = digest.getDigestSize();

        int delta;

        if (trailer == TRAILER_IMPLICIT)
        {
            delta = block.length - digSize - 1;
            digest.doFinal(block, delta);
            block[block.length - 1] = (byte)TRAILER_IMPLICIT;
        }
        else
        {
            delta = block.length - digSize - 2;
            digest.doFinal(block, delta);
            block[block.length - 2] = (byte)(trailer >>> 8);
            block[block.length - 1] = (byte)trailer;
        }

        block[0] = 0x06;
        for (int i = delta - 2; i != 0; i--)
        {
            block[i] = (byte)0xbb;
        }
        block[delta - 1] = (byte)0xba;
    }

    /**
     * return true if the signature represents a ISO9796-2 signature
     * for the passed in message.
     */
    public boolean verifySignature(
        byte[]      signature)
    {
        try
        {
            block = cipher.processBlock(signature, 0, signature.length);
        }
        catch (Exception e)
        {
            return false;
        }

        BigInteger t = new BigInteger(block);
        BigInteger f;

        if (t.mod(BigInteger.valueOf(16)).equals(BigInteger.valueOf(12)))
        {
             f = t;
        }
        else
        {
            t = kParam.getModulus().subtract(t);
            if (t.mod(BigInteger.valueOf(16)).equals(BigInteger.valueOf(12)))
            {
                 f = t;
            }
            else
            {
                return false;
            }
        }

        createSignatureBlock();

        byte[] fBlock = BigIntegers.asUnsignedByteArray(block.length, f);

        boolean rv = Arrays.constantTimeAreEqual(block, fBlock);

        clearBlock(block);
        clearBlock(fBlock);

        return rv;
    }
}
