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
     * Checks if the argument is a correctly PKCS#1.5 encoded Plaintext
     * for encryption.
     *
     * @param encoded The Plaintext.
     * @param pLen    Expected length of the plaintext.
     * @return Either 0, if the encoding is correct, or -1, if it is incorrect.
     */
    private static int checkPkcs1Encoding(byte[] encoded, int pLen)
    {
        int correct = 0;
        /*
		 * Check if the first two bytes are 0 2
		 */
        correct |= (encoded[0] ^ 2);

		/*
		 * Now the padding check, check for no 0 byte in the padding
		 */
        int plen = encoded.length - (
            pLen /* Length of the PMS */
                + 1 /* Final 0-byte before PMS */
        );

        for (int i = 1; i < plen; i++)
        {
            int tmp = encoded[i];
            tmp |= tmp >> 1;
            tmp |= tmp >> 2;
            tmp |= tmp >> 4;
            correct |= (tmp & 1) - 1;
        }

		/*
		 * Make sure the padding ends with a 0 byte.
		 */
        correct |= encoded[encoded.length - (pLen + 1)];

		/*
		 * Return 0 or 1, depending on the result.
		 */
        correct |= correct >> 1;
        correct |= correct >> 2;
        correct |= correct >> 4;
        return ~((correct & 1) - 1);
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

        byte[] block = engine.processBlock(in, inOff, inLen);
        byte[] random;
        if (this.fallback == null)
        {
            random = new byte[this.pLen];
            this.random.nextBytes(random);
        }
        else
        {
            random = fallback;
        }

        byte[] data = (useStrictLength & (block.length != engine.getOutputBlockSize())) ? blockBuffer : block;

		/*
		 * Check the padding.
		 */
        int correct = PKCS1Encoding.checkPkcs1Encoding(data, this.pLen);
		
		/*
		 * Now, to a constant time constant memory copy of the decrypted value
		 * or the random value, depending on the validity of the padding.
		 */
        byte[] result = new byte[this.pLen];
        for (int i = 0; i < this.pLen; i++)
        {
            result[i] = (byte)((data[i + (data.length - pLen)] & (~correct)) | (random[i] & correct));
        }

        Arrays.fill(data, (byte)0);

        return result;
    }

    /**
     * @throws InvalidCipherTextException if the decrypted block is not in PKCS1 format.
     */
    private byte[] decodeBlock(
        byte[] in,
        int inOff,
        int inLen)
        throws InvalidCipherTextException
    {
        /*
         * If the length of the expected plaintext is known, we use a constant-time decryption.
         * If the decryption fails, we return a random value.
         */
        if (this.pLen != -1)
        {
            return this.decodeBlockOrRandom(in, inOff, inLen);
        }

        byte[] block = engine.processBlock(in, inOff, inLen);
        boolean incorrectLength = (useStrictLength & (block.length != engine.getOutputBlockSize()));

        byte[] data;
        if (block.length < getOutputBlockSize())
        {
            data = blockBuffer;
        }
        else
        {
            data = block;
        }

        byte type = data[0];

        boolean badType;
        if (forPrivateKey)
        {
            badType = (type != 2);
        }
        else
        {
            badType = (type != 1);
        }

        //
        // find and extract the message block.
        //
        int start = findStart(type, data);

        start++;           // data should start at the next byte

        if (badType | start < HEADER_LENGTH)
        {
            Arrays.fill(data, (byte)0);
            throw new InvalidCipherTextException("block incorrect");
        }

        // if we get this far, it's likely to be a genuine encoding error
        if (incorrectLength)
        {
            Arrays.fill(data, (byte)0);
            throw new InvalidCipherTextException("block incorrect size");
        }

        byte[] result = new byte[data.length - start];

        System.arraycopy(data, start, result, 0, result.length);

        return result;
    }

    private int findStart(byte type, byte[] block)
        throws InvalidCipherTextException
    {
        int start = -1;
        boolean padErr = false;

        for (int i = 1; i != block.length; i++)
        {
            byte pad = block[i];

            if (pad == 0 & start < 0)
            {
                start = i;
            }
            padErr |= (type == 1 & start < 0 & pad != (byte)0xff);
        }

        if (padErr)
        {
            return -1;
        }

        return start;
    }
}
