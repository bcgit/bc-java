package org.bouncycastle.crypto.signers;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSABlindingParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.Arrays;

/**
 *
 * SHAKE with RSA-PSS as described in PKCS#1 v2.1 and RFC 8702
 * <p/>
 * Note: the usual value for the salt length is the number of
 * bytes in the hash function.
 */
// Code based on PSSSigner.java
public class SHAKEPSSSigner
    implements Signer {
    static final public byte TRAILER_IMPLICIT    = (byte)0xBC;

    private final SHAKEDigest           digest;
    private final AsymmetricBlockCipher cipher;
    private SecureRandom                random;

    private final int                   hLen;
    private final boolean               sSet;
    private final int                   sLen;
    private int                         emBits;
    private byte[]                      salt;
    private byte[]                      mDash;
    private byte[]                      block;

    /**
     * basic constructor
     *
     * @param cipher the asymmetric cipher to use.
     * @param digest the digest to use.
     */
    public SHAKEPSSSigner(
        AsymmetricBlockCipher cipher,
        int type,
        int size)
    {
        this.cipher = cipher;
        this.digest = new SHAKEDigest(type);
        this.hLen = size / 8;

        this.sSet = false;
        this.sLen = hLen;
        this.salt = new byte[hLen];
        this.mDash = new byte[8 + sLen + hLen];
    }

    public SHAKEPSSSigner(
        AsymmetricBlockCipher   cipher,
        int                     type,
        int                     size,
        byte[]                  salt)
    {
        this.cipher = cipher;
        this.digest = new SHAKEDigest(type);
        this.hLen = size / 8;

        if (salt.length != hLen) {
          throw new IllegalArgumentException("salt.length != " + hLen);
        }
        this.sSet = true;
        this.sLen = salt.length;
        this.salt = salt;
        this.mDash = new byte[8 + sLen + hLen];
    }

    public void init(
        boolean                 forSigning,
        CipherParameters        param)
    {
        CipherParameters  params;

        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom    p = (ParametersWithRandom)param;

            params = p.getParameters();
            random = p.getRandom();
        }
        else
        {
            params = param;
            if (forSigning)
            {
                random = CryptoServicesRegistrar.getSecureRandom();
            }
        }

        RSAKeyParameters kParam;

        if (params instanceof RSABlindingParameters)
        {
            kParam = ((RSABlindingParameters)params).getPublicKey();

            cipher.init(forSigning, param);   // pass on random
        }
        else
        {
            kParam = (RSAKeyParameters)params;

            cipher.init(forSigning, params);
        }

        emBits = kParam.getModulus().bitLength() - 1;

        if (emBits < (8 * hLen + 8 * sLen + 9))
        {
            throw new IllegalArgumentException("key too small for specified hash and salt lengths");
        }

        block = new byte[(emBits + 7) / 8];

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
     * generate a signature for the message we've been loaded with using
     * the key we were initialised with.
     */
    public byte[] generateSignature()
        throws CryptoException, DataLengthException
    {
        doFinal(mDash, mDash.length - hLen - sLen);

        if (sLen != 0)
        {
            if (!sSet)
            {
                random.nextBytes(salt);
            }

            System.arraycopy(salt, 0, mDash, mDash.length - sLen, sLen);
        }

        byte[]  h = new byte[hLen];

        digest.update(mDash, 0, mDash.length);

        doFinal(h, 0);

        block[block.length - sLen - 1 - hLen - 1] = 0x01;
        System.arraycopy(salt, 0, block, block.length - sLen - hLen - 1, sLen);

        byte[] dbMask = maskGeneratorFunction(h, 0, h.length, block.length - hLen - 1);
        for (int i = 0; i != dbMask.length; i++)
        {
            block[i] ^= dbMask[i];
        }

        System.arraycopy(h, 0, block, block.length - hLen - 1, hLen);

        int firstByteMask = 0xff >>> ((block.length * 8) - emBits);

        block[0] &= firstByteMask;
        block[block.length - 1] = TRAILER_IMPLICIT;

        byte[]  b = cipher.processBlock(block, 0, block.length);

        clearBlock(block);

        return b;
    }

    /**
     * return true if the internal state represents the signature described
     * in the passed in array.
     */
    public boolean verifySignature(
        byte[]      signature)
    {
        doFinal(mDash, mDash.length - hLen - sLen);

        try
        {
            byte[] b = cipher.processBlock(signature, 0, signature.length);
            Arrays.fill(block, 0, block.length - b.length, (byte)0);
            System.arraycopy(b, 0, block, block.length - b.length, b.length);
        }
        catch (Exception e)
        {
            return false;
        }

        int firstByteMask = 0xff >>> ((block.length * 8) - emBits);

        if ((block[0] & 0xff) != (block[0] & firstByteMask)
            || block[block.length - 1] != TRAILER_IMPLICIT)
        {
            clearBlock(block);
            return false;
        }

        byte[] dbMask = maskGeneratorFunction(block, block.length - hLen - 1, hLen,
                        block.length - hLen - 1);

        for (int i = 0; i != dbMask.length; i++)
        {
            block[i] ^= dbMask[i];
        }

        block[0] &= firstByteMask;

        for (int i = 0; i != block.length - hLen - sLen - 2; i++)
        {
            if (block[i] != 0)
            {
                clearBlock(block);
                return false;
            }
        }

        if (block[block.length - hLen - sLen - 2] != 0x01)
        {
            clearBlock(block);
            return false;
        }

        if (sSet)
        {
            System.arraycopy(salt, 0, mDash, mDash.length - sLen, sLen);
        }
        else
        {
            System.arraycopy(block, block.length - sLen - hLen - 1,
                mDash, mDash.length - sLen, sLen);
        }

        digest.update(mDash, 0, mDash.length);
        doFinal(mDash, mDash.length - hLen);

        for (int i = block.length - hLen - 1, j = mDash.length - hLen;
                                                 j != mDash.length; i++, j++)
        {
            if ((block[i] ^ mDash[j]) != 0)
            {
                clearBlock(mDash);
                clearBlock(block);
                return false;
            }
        }

        clearBlock(mDash);
        clearBlock(block);

        return true;
    }

    /**
     * mask generator function, as described in RFC 8692 and RFC 8702.
     */
    private byte[] maskGeneratorFunction(
        byte[]  Z,
        int     zOff,
        int     zLen,
        int     length) {
        byte[]  mask = new byte[length];
        digest.reset();
        digest.update(Z, zOff, zLen);
        digest.doFinal(mask, 0, length);
        return mask;
    }

    private int doFinal(byte[] out, int outOff) {
        return digest.doFinal(out, outOff, hLen);
    }

}
