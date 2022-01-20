package org.bouncycastle.crypto.encodings;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Optimal Asymmetric Encryption Padding (OAEP) - see PKCS 1 V 2.
 */
public class OAEPEncoding
    implements AsymmetricBlockCipher
{
    private byte[]                  defHash;
    private Digest                  mgf1Hash;

    private AsymmetricBlockCipher   engine;
    private SecureRandom            random;
    private boolean                 forEncryption;

    public OAEPEncoding(
        AsymmetricBlockCipher   cipher)
    {
        this(cipher, DigestFactory.createSHA1(), null);
    }
    
    public OAEPEncoding(
        AsymmetricBlockCipher       cipher,
        Digest                      hash)
    {
        this(cipher, hash, null);
    }
    
    public OAEPEncoding(
        AsymmetricBlockCipher       cipher,
        Digest                      hash,
        byte[]                      encodingParams)
    {
        this(cipher, hash, hash, encodingParams);
    }

    public OAEPEncoding(
        AsymmetricBlockCipher       cipher,
        Digest                      hash,
        Digest                      mgf1Hash,
        byte[]                      encodingParams)
    {
        this.engine = cipher;
        this.mgf1Hash = mgf1Hash;
        this.defHash = new byte[hash.getDigestSize()];

        hash.reset();

        if (encodingParams != null)
        {
            hash.update(encodingParams, 0, encodingParams.length);
        }

        hash.doFinal(defHash, 0);
    }

    public AsymmetricBlockCipher getUnderlyingCipher()
    {
        return engine;
    }

    public void init(
        boolean             forEncryption,
        CipherParameters    param)
    {
        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom  rParam = (ParametersWithRandom)param;

            this.random = rParam.getRandom();
        }
        else
        {   
            this.random = CryptoServicesRegistrar.getSecureRandom();
        }

        engine.init(forEncryption, param);

        this.forEncryption = forEncryption;
    }

    public int getInputBlockSize()
    {
        int     baseBlockSize = engine.getInputBlockSize();

        if (forEncryption)
        {
            return baseBlockSize - 1 - 2 * defHash.length;
        }
        else
        {
            return baseBlockSize;
        }
    }

    public int getOutputBlockSize()
    {
        int     baseBlockSize = engine.getOutputBlockSize();

        if (forEncryption)
        {
            return baseBlockSize;
        }
        else
        {
            return baseBlockSize - 1 - 2 * defHash.length;
        }
    }

    public byte[] processBlock(
        byte[]  in,
        int     inOff,
        int     inLen)
        throws InvalidCipherTextException
    {
        if (forEncryption)
        {
            return encodeBlock(in, inOff, inLen);
        }
        else
        {
            return decodeBlock(in, inOff, inLen);
        }
    }

    public byte[] encodeBlock(
        byte[]  in,
        int     inOff,
        int     inLen)
        throws InvalidCipherTextException
    {
        if (inLen > getInputBlockSize())
        {
            throw new DataLengthException("input data too long");
        }

        byte[]  block = new byte[getInputBlockSize() + 1 + 2 * defHash.length];

        //
        // copy in the message
        //
        System.arraycopy(in, inOff, block, block.length - inLen, inLen);

        //
        // add sentinel
        //
        block[block.length - inLen - 1] = 0x01;

        //
        // as the block is already zeroed - there's no need to add PS (the >= 0 pad of 0)
        //

        //
        // add the hash of the encoding params.
        //
        System.arraycopy(defHash, 0, block, defHash.length, defHash.length);

        //
        // generate the seed.
        //
        byte[]  seed = new byte[defHash.length];

        random.nextBytes(seed);

        //
        // mask the message block.
        //
        byte[]  mask = maskGeneratorFunction1(seed, 0, seed.length, block.length - defHash.length);

        for (int i = defHash.length; i != block.length; i++)
        {
            block[i] ^= mask[i - defHash.length];
        }

        //
        // add in the seed
        //
        System.arraycopy(seed, 0, block, 0, defHash.length);

        //
        // mask the seed.
        //
        mask = maskGeneratorFunction1(
                        block, defHash.length, block.length - defHash.length, defHash.length);

        for (int i = 0; i != defHash.length; i++)
        {
            block[i] ^= mask[i];
        }

        return engine.processBlock(block, 0, block.length);
    }

    /**
     * @exception InvalidCipherTextException if the decrypted block turns out to
     * be badly formatted.
     */
    public byte[] decodeBlock(
        byte[]  in,
        int     inOff,
        int     inLen)
        throws InvalidCipherTextException
    {
        byte[]  data = engine.processBlock(in, inOff, inLen);
        byte[]  block = new byte[engine.getOutputBlockSize()];

        //
        // as we may have zeros in our leading bytes for the block we produced
        // on encryption, we need to make sure our decrypted block comes back
        // the same size.
        //

        // i.e. wrong when block.length < (2 * defHash.length) + 1
        int wrongMask = (block.length - ((2 * defHash.length) + 1)) >> 31;

        if (data.length <= block.length)
        {
            System.arraycopy(data, 0, block, block.length - data.length, data.length);
        }
        else
        {
            System.arraycopy(data, 0, block, 0, block.length);
            wrongMask |= 1;
        }

        //
        // unmask the seed.
        //
        byte[] mask = maskGeneratorFunction1(
                    block, defHash.length, block.length - defHash.length, defHash.length);

        for (int i = 0; i != defHash.length; i++)
        {
            block[i] ^= mask[i];
        }

        //
        // unmask the message block.
        //
        mask = maskGeneratorFunction1(block, 0, defHash.length, block.length - defHash.length);

        for (int i = defHash.length; i != block.length; i++)
        {
            block[i] ^= mask[i - defHash.length];
        }

        //
        // check the hash of the encoding params.
        // long check to try to avoid this been a source of a timing attack.
        //
        for (int i = 0; i != defHash.length; i++)
        {
            wrongMask |= defHash[i] ^ block[defHash.length + i];
        }

        //
        // find the data block
        //
        int start = -1;

        for (int index = 2 * defHash.length; index != block.length; index++)
        {
            int octet = block[index] & 0xFF;

            // i.e. mask will be 0xFFFFFFFF if octet is non-zero and start is (still) negative, else 0.
            int shouldSetMask = (-octet & start) >> 31;

            start += index & shouldSetMask;
        }

        wrongMask |= start >> 31;
        ++start;
        wrongMask |= block[start] ^ 1;

        if (wrongMask != 0)
        {
            Arrays.fill(block, (byte)0);
            throw new InvalidCipherTextException("data wrong");
        }

        ++start;

        //
        // extract the data block
        //
        byte[]  output = new byte[block.length - start];

        System.arraycopy(block, start, output, 0, output.length);
        Arrays.fill(block, (byte)0);

        return output;
    }

    /**
     * mask generator function, as described in PKCS1v2.
     */
    private byte[] maskGeneratorFunction1(
        byte[]  Z,
        int     zOff,
        int     zLen,
        int     length)
    {
        byte[]  mask = new byte[length];
        byte[]  hashBuf = new byte[mgf1Hash.getDigestSize()];
        byte[]  C = new byte[4];
        int     counter = 0;

        mgf1Hash.reset();

        while (counter < (length / hashBuf.length))
        {
            Pack.intToBigEndian(counter, C, 0);

            mgf1Hash.update(Z, zOff, zLen);
            mgf1Hash.update(C, 0, C.length);
            mgf1Hash.doFinal(hashBuf, 0);

            System.arraycopy(hashBuf, 0, mask, counter * hashBuf.length, hashBuf.length);

            counter++;
        }

        if ((counter * hashBuf.length) < length)
        {
            Pack.intToBigEndian(counter, C, 0);

            mgf1Hash.update(Z, zOff, zLen);
            mgf1Hash.update(C, 0, C.length);
            mgf1Hash.doFinal(hashBuf, 0);

            System.arraycopy(hashBuf, 0, mask, counter * hashBuf.length, mask.length - (counter * hashBuf.length));
        }

        return mask;
    }
}
