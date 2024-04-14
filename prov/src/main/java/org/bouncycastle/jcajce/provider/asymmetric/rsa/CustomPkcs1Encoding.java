package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;

/**
 * this does your basic PKCS 1 v1.5 padding - whether or not you should be using this
 * depends on your application - see PKCS1 Version 2 for details.
 */
class CustomPKCS1Encoding
    implements AsymmetricBlockCipher
{
    private static final int HEADER_LENGTH = 10;

    private SecureRandom random;
    private AsymmetricBlockCipher engine;
    private boolean forEncryption;
    private boolean forPrivateKey;
    private boolean useStrictLength;
    private byte[] blockBuffer;

    /**
     * Basic constructor.
     *
     * @param cipher
     */
    CustomPKCS1Encoding(AsymmetricBlockCipher cipher)
    {
        this.engine = cipher;
        this.useStrictLength = useStrict();
    }

    //
    // for J2ME compatibility
    //
    private boolean useStrict()
    {
        if (Properties.isOverrideSetTo(PKCS1Encoding.NOT_STRICT_LENGTH_ENABLED_PROPERTY, true))
        {
            return false;
        }

        return !Properties.isOverrideSetTo(PKCS1Encoding.STRICT_LENGTH_ENABLED_PROPERTY, false);
    }

    public AsymmetricBlockCipher getUnderlyingCipher()
    {
        return engine;
    }

    public void init(boolean forEncryption, CipherParameters param)
    {
        AsymmetricKeyParameter kParam;

        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom rParam = (ParametersWithRandom)param;

            this.random = rParam.getRandom();
            kParam = (AsymmetricKeyParameter)rParam.getParameters();
        }
        else
        {
            kParam = (AsymmetricKeyParameter)param;
            if (!kParam.isPrivate() && forEncryption)
            {
                this.random = CryptoServicesRegistrar.getSecureRandom();
            }
        }

        engine.init(forEncryption, param);

        this.forPrivateKey = kParam.isPrivate();
        this.forEncryption = forEncryption;
        this.blockBuffer = new byte[engine.getOutputBlockSize()];
    }

    public int getInputBlockSize()
    {
        int baseBlockSize = engine.getInputBlockSize();

        if (forEncryption)
        {
            return baseBlockSize - HEADER_LENGTH;
        }
        else
        {
            return baseBlockSize;
        }
    }

    public int getOutputBlockSize()
    {
        int baseBlockSize = engine.getOutputBlockSize();

        if (forEncryption)
        {
            return baseBlockSize;
        }
        else
        {
            return baseBlockSize - HEADER_LENGTH;
        }
    }

    public byte[] processBlock(byte[] in, int inOff, int inLen) throws InvalidCipherTextException
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

    private byte[] encodeBlock(byte[] in, int inOff, int inLen) throws InvalidCipherTextException
    {
        if (inLen > getInputBlockSize())
        {
            throw new IllegalArgumentException("input data too large");
        }

        byte[] block = new byte[engine.getInputBlockSize()];

        if (forPrivateKey)
        {
            block[0] = 0x01;                        // type code 1

            for (int i = 1; i != block.length - inLen - 1; i++)
            {
                block[i] = (byte)0xFF;
            }
        }
        else
        {
            random.nextBytes(block);                // random fill

            block[0] = 0x02;                        // type code 2

            //
            // a zero byte marks the end of the padding, so all
            // the pad bytes must be non-zero.
            //
            for (int i = 1; i != block.length - inLen - 1; i++)
            {
                while (block[i] == 0)
                {
                    block[i] = (byte)random.nextInt();
                }
            }
        }

        block[block.length - inLen - 1] = 0x00;       // mark the end of the padding
        System.arraycopy(in, inOff, block, block.length - inLen, inLen);

        return engine.processBlock(block, 0, block.length);
    }

    /**
     * Check the argument is a valid encoding with type 1. Returns the plaintext length if valid, or -1 if invalid.
     */
    private static int checkPkcs1Encoding1(byte[] buf)
    {
        int foundZeroMask = 0;
        int lastPadPos = 0;

        // The first byte should be 0x01
        int badPadSign = -((buf[0] & 0xFF) ^ 0x01);

        // There must be a zero terminator for the padding somewhere
        for (int i = 1; i < buf.length; ++i)
        {
            int padByte = buf[i] & 0xFF;
            int is0x00Mask = ((padByte ^ 0x00) - 1) >> 31;
            int is0xFFMask = ((padByte ^ 0xFF) - 1) >> 31;
            lastPadPos ^= i & ~foundZeroMask & is0x00Mask;
            foundZeroMask |= is0x00Mask;
            badPadSign |= ~(foundZeroMask | is0xFFMask);
        }

        // The header should be at least 10 bytes
        badPadSign |= lastPadPos - 9;

        int plaintextLength = buf.length - 1 - lastPadPos;
        return plaintextLength | badPadSign >> 31;
    }

    /**
     * Check the argument is a valid encoding with type 2. Returns the plaintext length if valid, or -1 if invalid.
     */
    private static int checkPkcs1Encoding2(byte[] buf)
    {
        int foundZeroMask = 0;
        int lastPadPos = 0;

        // The first byte should be 0x02
        int badPadSign = -((buf[0] & 0xFF) ^ 0x02);

        // There must be a zero terminator for the padding somewhere
        for (int i = 1; i < buf.length; ++i)
        {
            int padByte = buf[i] & 0xFF;
            int is0x00Mask = ((padByte ^ 0x00) - 1) >> 31;
            lastPadPos ^= i & ~foundZeroMask & is0x00Mask;
            foundZeroMask |= is0x00Mask;
        }

        // The header should be at least 10 bytes
        badPadSign |= lastPadPos - 9;

        int plaintextLength = buf.length - 1 - lastPadPos;
        return plaintextLength | badPadSign >> 31;
    }

    /**
     * @throws InvalidCipherTextException if the decrypted block is not in PKCS1 format.
     */
    private byte[] decodeBlock(byte[] in, int inOff, int inLen)
        throws InvalidCipherTextException
    {
        int strictBlockSize = engine.getOutputBlockSize();
        byte[] block = engine.processBlock(in, inOff, inLen);

        boolean incorrectLength = useStrictLength & (block.length != strictBlockSize);

        byte[] data = block;
        if (block.length < strictBlockSize)
        {
            data = blockBuffer;
        }

        int plaintextLength = forPrivateKey ? checkPkcs1Encoding2(data) : checkPkcs1Encoding1(data);

        try
        {
            if (plaintextLength < 0 | incorrectLength)
            {
                // Special behaviour to avoid throw/catch/throw in CipherSpi
                return null;
            }

            byte[] result = new byte[plaintextLength];
            System.arraycopy(data, data.length - plaintextLength, result, 0, plaintextLength);
            return result;
        }
        finally
        {
            Arrays.fill(block, (byte)0);
            Arrays.fill(blockBuffer, 0, Math.max(0, blockBuffer.length - block.length), (byte)0);
        }
    }
}
