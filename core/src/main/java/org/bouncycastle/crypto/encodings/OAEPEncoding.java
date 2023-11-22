package org.bouncycastle.crypto.encodings;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/**
 * Optimal Asymmetric Encryption Padding (OAEP) - see PKCS 1 V 2.
 */
public class OAEPEncoding
    implements AsymmetricBlockCipher
{
    private static int getMGF1NoMemoLimit(Digest d)
    {
        if (d instanceof Memoable && d instanceof ExtendedDigest)
        {
            return ((ExtendedDigest)d).getByteLength() - 1;
        }

        return Integer.MAX_VALUE;
    }

    private final AsymmetricBlockCipher   engine;
    private final Digest                  mgf1Hash;
    private final int                     mgf1NoMemoLimit;
    private final byte[]                  defHash;

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
        this.mgf1NoMemoLimit = getMGF1NoMemoLimit(mgf1Hash);
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

    public void init(boolean forEncryption, CipherParameters param)
    {
        SecureRandom initRandom = null;
        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom rParam = (ParametersWithRandom)param;
            initRandom = rParam.getRandom();
        }

        this.random = forEncryption ? CryptoServicesRegistrar.getSecureRandom(initRandom) : null;
        this.forEncryption = forEncryption;

        engine.init(forEncryption, param);
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

    public byte[] encodeBlock(byte[] in, int inOff, int inLen) throws InvalidCipherTextException
    {
        int inputBlockSize = getInputBlockSize();
        if (inLen > inputBlockSize)
        {
            throw new DataLengthException("input data too long");
        }

        byte[] block = new byte[inputBlockSize + 1 + 2 * defHash.length];

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
        byte[] seed = new byte[defHash.length];
        random.nextBytes(seed);
        System.arraycopy(seed, 0, block, 0, defHash.length);

        mgf1Hash.reset();

        //
        // mask the message block.
        //
        maskGeneratorFunction1(seed, 0, seed.length, block, defHash.length, block.length - defHash.length);

        //
        // mask the seed.
        //
        maskGeneratorFunction1(block, defHash.length, block.length - defHash.length, block, 0, defHash.length);

        return engine.processBlock(block, 0, block.length);
    }

    /**
     * @exception InvalidCipherTextException if the decrypted block turns out to
     * be badly formatted.
     */
    public byte[] decodeBlock(byte[] in, int inOff, int inLen) throws InvalidCipherTextException
    {
        // i.e. wrong when block.length < (2 * defHash.length) + 1
        int wrongMask = getOutputBlockSize() >> 31;

        //
        // as we may have zeros in our leading bytes for the block we produced
        // on encryption, we need to make sure our decrypted block comes back
        // the same size.
        //
        byte[] block = new byte[engine.getOutputBlockSize()];
        {
            byte[] data = engine.processBlock(in, inOff, inLen);
            wrongMask |= (block.length - data.length) >> 31;

            int copyLen = Math.min(block.length, data.length);
            System.arraycopy(data, 0, block, block.length - copyLen, copyLen);
            Arrays.fill(data, (byte)0);
        }

        mgf1Hash.reset();

        //
        // unmask the seed.
        //
        maskGeneratorFunction1(block, defHash.length, block.length - defHash.length, block, 0, defHash.length);

        //
        // unmask the message block.
        //
        maskGeneratorFunction1(block, 0, defHash.length, block, defHash.length, block.length - defHash.length);

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
        byte[] output = new byte[block.length - start];

        System.arraycopy(block, start, output, 0, output.length);
        Arrays.fill(block, (byte)0);

        return output;
    }

    /**
     * mask generator function, as described in PKCS1v2.
     */
    private void maskGeneratorFunction1(byte[] z, int zOff, int zLen, byte[] mask, int maskOff, int maskLen)
    {
        int digestSize = mgf1Hash.getDigestSize();

        byte[] hash = new byte[digestSize];
        byte[] C = new byte[4];
        int counter = 0;

        int maskEnd = maskOff + maskLen;
        int maskLimit = maskEnd - digestSize;
        int maskPos = maskOff;

        mgf1Hash.update(z, zOff, zLen);

        if (zLen > mgf1NoMemoLimit)
        {
            Memoable memoable = (Memoable)mgf1Hash;
            Memoable memo = memoable.copy();

            while (maskPos < maskLimit)
            {
                Pack.intToBigEndian(counter++, C, 0);
                mgf1Hash.update(C, 0, C.length);
                mgf1Hash.doFinal(hash, 0);
                memoable.reset(memo);
                Bytes.xorTo(digestSize, hash, 0, mask, maskPos);
                maskPos += digestSize;
            }
        }
        else
        {
            while (maskPos < maskLimit)
            {
                Pack.intToBigEndian(counter++, C, 0);
                mgf1Hash.update(C, 0, C.length);
                mgf1Hash.doFinal(hash, 0);
                mgf1Hash.update(z, zOff, zLen);
                Bytes.xorTo(digestSize, hash, 0, mask, maskPos);
                maskPos += digestSize;
            }
        }

        Pack.intToBigEndian(counter, C, 0);
        mgf1Hash.update(C, 0, C.length);
        mgf1Hash.doFinal(hash, 0);
        Bytes.xorTo(maskEnd - maskPos, hash, 0, mask, maskPos);
    }
}
