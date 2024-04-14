package org.bouncycastle.crypto.encodings;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;

/**
 * this does your basic PKCS 1 v1.5 padding - whether or not you should be using this
 * depends on your application - see PKCS1 Version 2 for details.
 */
public class PKCS1Encoding
    implements AsymmetricBlockCipher
{
    /**
     * @deprecated use NOT_STRICT_LENGTH_ENABLED_PROPERTY
     */
    public static final String STRICT_LENGTH_ENABLED_PROPERTY = "org.bouncycastle.pkcs1.strict";

    /**
     * some providers fail to include the leading zero in PKCS1 encoded blocks. If you need to
     * work with one of these set the system property org.bouncycastle.pkcs1.not_strict to true.
     * <p>
     * The system property is checked during construction of the encoding object, it is set to
     * false by default.
     * </p>
     */
    public static final String NOT_STRICT_LENGTH_ENABLED_PROPERTY = "org.bouncycastle.pkcs1.not_strict";

    private static final int HEADER_LENGTH = 10;

    private SecureRandom random;
    private AsymmetricBlockCipher engine;
    private boolean forEncryption;
    private boolean forPrivateKey;
    private boolean useStrictLength;
    private int pLen = -1;
    private byte[] fallback = null;
    private byte[] blockBuffer;

    /**
     * Basic constructor.
     *
     * @param cipher
     */
    public PKCS1Encoding(
        AsymmetricBlockCipher cipher)
    {
        this.engine = cipher;
        this.useStrictLength = useStrict();
    }

    /**
     * Constructor for decryption with a fixed plaintext length.
     *
     * @param cipher The cipher to use for cryptographic operation.
     * @param pLen   Length of the expected plaintext.
     */
    public PKCS1Encoding(
        AsymmetricBlockCipher cipher,
        int pLen)
    {
        this.engine = cipher;
        this.useStrictLength = useStrict();
        this.pLen = pLen;
    }

    /**
     * Constructor for decryption with a fixed plaintext length and a fallback
     * value that is returned, if the padding is incorrect.
     *
     * @param cipher   The cipher to use for cryptographic operation.
     * @param fallback The fallback value, we don't do an arraycopy here.
     */
    public PKCS1Encoding(
        AsymmetricBlockCipher cipher,
        byte[] fallback)
    {
        this.engine = cipher;
        this.useStrictLength = useStrict();
        this.fallback = fallback;
        this.pLen = fallback.length;
    }


    //
    // for J2ME compatibility
    //
    private boolean useStrict()
    {
        if (Properties.isOverrideSetTo(NOT_STRICT_LENGTH_ENABLED_PROPERTY, true))
        {
            return false;
        }

        return !Properties.isOverrideSetTo(STRICT_LENGTH_ENABLED_PROPERTY, false);
    }

    public AsymmetricBlockCipher getUnderlyingCipher()
    {
        return engine;
    }

    public void init(
        boolean forEncryption,
        CipherParameters param)
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

        if (pLen > 0 && fallback == null && random == null)
        {
           throw new IllegalArgumentException("encoder requires random");
        }
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

    public byte[] processBlock(
        byte[] in,
        int inOff,
        int inLen)
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

    private byte[] encodeBlock(
        byte[] in,
        int inOff,
        int inLen)
        throws InvalidCipherTextException
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
     * Check the argument is a valid encoding with type 2 of a plaintext with the given length. Returns 0 if
     * valid, or -1 if invalid.
     */
    private static int checkPkcs1Encoding2(byte[] buf, int plaintextLength)
    {
        // The first byte should be 0x02
        int badPadSign = -((buf[0] & 0xFF) ^ 0x02);

        int lastPadPos = buf.length - 1 - plaintextLength;

        // The header should be at least 10 bytes
        badPadSign |= lastPadPos - 9;

        // All pad bytes before the last one should be non-zero
        for (int i = 1; i < lastPadPos; ++i)
        {
            badPadSign |= (buf[i] & 0xFF) - 1;
        }

        // Last pad byte should be zero
        badPadSign |= -(buf[lastPadPos] & 0xFF);

        return badPadSign >> 31;
    }

    /**
     * Decode PKCS#1.5 encoding, and return a random value if the padding is not correct.
     *
     * @param in    The encrypted block.
     * @param inOff Offset in the encrypted block.
     * @param inLen Length of the encrypted block.
     *              //@param pLen Length of the desired output.
     * @return The plaintext without padding, or a random value if the padding was incorrect.
     * @throws InvalidCipherTextException
     */
    private byte[] decodeBlockOrRandom(byte[] in, int inOff, int inLen)
        throws InvalidCipherTextException
    {
        if (!forPrivateKey)
        {
            throw new InvalidCipherTextException("sorry, this method is only for decryption, not for signing");
        }

        int plaintextLength = this.pLen;

        byte[] random = fallback;
        if (fallback == null)
        {
            random = new byte[plaintextLength];
            this.random.nextBytes(random);
        }

        int badPadMask = 0;
        int strictBlockSize = engine.getOutputBlockSize();
        byte[] block = engine.processBlock(in, inOff, inLen);

        byte[] data = block;
        if (block.length != strictBlockSize)
        {
            if (useStrictLength || block.length < strictBlockSize)
            {
                data = blockBuffer;
            }
        }

        badPadMask |= checkPkcs1Encoding2(data, plaintextLength);

        /*
         * Now, to a constant time constant memory copy of the decrypted value
         * or the random value, depending on the validity of the padding.
         */
        int dataOff = data.length - plaintextLength; 
        byte[] result = new byte[plaintextLength];
        for (int i = 0; i < plaintextLength; ++i)
        {
            result[i] = (byte)((data[dataOff + i] & ~badPadMask) | (random[i] & badPadMask));
        }

        Arrays.fill(block, (byte)0);
        Arrays.fill(blockBuffer, 0, Math.max(0, blockBuffer.length - block.length), (byte)0);

        return result;
    }

    /**
     * @throws InvalidCipherTextException if the decrypted block is not in PKCS1 format.
     */
    private byte[] decodeBlock(byte[] in, int inOff, int inLen)
        throws InvalidCipherTextException
    {
        /*
         * If the length of the expected plaintext is known, we use a constant-time decryption.
         * If the decryption fails, we return a random value.
         */
        if (forPrivateKey && this.pLen != -1)
        {
            return this.decodeBlockOrRandom(in, inOff, inLen);
        }

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
            if (plaintextLength < 0)
            {
                throw new InvalidCipherTextException("block incorrect");
            }
            if (incorrectLength)
            {
                throw new InvalidCipherTextException("block incorrect size");
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
