package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Implementation of the ChaCha20/Poly1305 AEAD construction described in <a
 * href="http://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305">
 * draft-irtf-cfrg-chacha20-poly1305</a>.
 * <p>
 * This implementation can be used with {@link ChaChaEngine} or any other {@link Salsa20Engine}
 * variant, and supports any nonce/counter split supported by the cipher engine (specifically it
 * will not adapt shorter nonces to the 96 bit nonce length).
 */
public class ChaChaPoly1305Engine
    implements AEADBlockCipher
{
    private static final int MAC_SIZE = 16;
    private static final int BLOCK_SIZE = 64;
    private static final byte[] ZEROES = new byte[16];

    private final Salsa20Engine cipher;
    private final Poly1305 mac = new Poly1305();
    private boolean forEncryption;
    private byte[] initialAssociatedText;

    private boolean initialised;
    private boolean cipherInitialized;
    private int aadSize;
    private int ctSize;

    private final byte[] bufBlock = new byte[BLOCK_SIZE + MAC_SIZE];
    private int bufOff;
    private final byte[] macBlock = new byte[MAC_SIZE];

    /**
     * Default constructor, creates an authenticated cipher using ChaCha/20 with a Poly1305 MAC.
     */
    public ChaChaPoly1305Engine()
    {
        this(new ChaChaEngine());
    }

    /**
     * Constructs an authenticated cipher using a custom ChaCha (or any Salsa20 variant) cipher with
     * a Poly1305 MAC.
     *
     * @param cipher the cipher engine to use.
     */
    public ChaChaPoly1305Engine(Salsa20Engine cipher)
    {
        this.cipher = cipher;
    }

    /**
     * Initialises this cipher.
     *
     * @param forEncryption whether this engine is being initialised for encryption or decryption.
     * @param params {@link ParametersWithIV} or {@link AEADParameters} specifying a key and nonce
     *            which will be passed directly to the cipher to initialise it. The mac size must be
     *            128 if AEADParameters are used.
     */
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        this.forEncryption = forEncryption;

        byte[] nonce;
        KeyParameter key;
        if (params instanceof AEADParameters)
        {
            AEADParameters param = (AEADParameters)params;

            nonce = param.getNonce();
            initialAssociatedText = param.getAssociatedText();
            if (param.getMacSize() != (MAC_SIZE * 8))
            {
                throw new IllegalArgumentException(getAlgorithmName() + " is only specified for 128 bit mac");
            }
            key = param.getKey();
        }
        else if (params instanceof ParametersWithIV)
        {
            ParametersWithIV param = (ParametersWithIV)params;

            nonce = param.getIV();
            initialAssociatedText = null;
            if ((param.getParameters() != null) && !(param.getParameters() instanceof KeyParameter))
            {
                throw new IllegalArgumentException(getAlgorithmName() + " needs a KeyParameter inside ParametersWithIV");
            }
            key = (KeyParameter)param.getParameters();
        }
        else
        {
            throw new IllegalArgumentException("invalid parameters passed to " + getAlgorithmName());
        }

        if (nonce == null)
        {
            throw new IllegalArgumentException("nonce must be specified.");
        }
        if ((key == null) && !initialised)
        {
            throw new IllegalStateException(getAlgorithmName()
                + " KeyParameter can not be null for first initialisation");
        }

        cipher.init(true, new ParametersWithIV(key, nonce));

        // poly1305_key_gen: Generate one time Poly1305 key using 'block' 0 of underlying cipher
        byte[] firstBlock = new byte[BLOCK_SIZE];
        cipher.processBytes(firstBlock, 0, firstBlock.length, firstBlock, 0);

        // poly1305_key_gen uses r = firstBlock[0..15] and s/k = firstBlock[16..31]
        // The BC Poly1305 implementation expects 'r' after 'k', so shift 'r' block after 'k'
        System.arraycopy(firstBlock, 0, firstBlock, 32, 16);
        KeyParameter macKey = new KeyParameter(firstBlock, 16, 32);
        Poly1305KeyGenerator.clamp(macKey.getKey());

        mac.init(macKey);

        reset();
        initialised = true;
    }

    public String getAlgorithmName()
    {
        return cipher.getAlgorithmName() + "-" + mac.getAlgorithmName();
    }

    public BlockCipher getUnderlyingCipher()
    {
        // TODO: drop this when an AEADCipher interface exists
        throw new UnsupportedOperationException();
    }

    public void processAADByte(byte in)
    {
        if (cipherInitialized)
        {
            throw new IllegalStateException("AAD data cannot be added after encryption/decryption processing has begun.");
        }
        mac.update(in);
        aadSize++;
    }

    public void processAADBytes(byte[] in, int inOff, int len)
    {
        if (cipherInitialized)
        {
            throw new IllegalStateException("AAD data cannot be added after encryption/decryption processing has begun.");
        }
        mac.update(in, inOff, len);
        aadSize += len;
    }

    public int processByte(byte in, byte[] out, int outOff)
        throws DataLengthException
    {
        if (out.length <= outOff)
        {
            throw new OutputLengthException("Output buffer is too short");
        }

        initCipher();

        if (forEncryption)
        {
            byte enc = cipher.returnByte(in);
            out[outOff] = enc;
            mac.update(enc);
            ctSize++;
            return 1;
        }
        else
        {
            bufBlock[bufOff++] = in;
            if (bufOff == bufBlock.length)
            {
                return decryptBlock(out, outOff);
            }
            return 0;
        }
    }

    private int decryptBlock(byte[] output, int offset)
    {
        int outputSize = bufBlock.length - MAC_SIZE;

        mac.update(bufBlock, 0, outputSize);
        ctSize += outputSize;
        cipher.processBytes(bufBlock, 0, outputSize, output, offset);
        System.arraycopy(bufBlock, outputSize, bufBlock, 0, MAC_SIZE);
        bufOff = MAC_SIZE;
        return outputSize;
    }

    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
        throws DataLengthException
    {
        initCipher();

        if (forEncryption)
        {
            cipher.processBytes(in, inOff, len, out, outOff);
            mac.update(out, outOff, len);
            ctSize += len;
            return len;
        }
        else
        {
            int resultLen = 0;
            for (int i = 0; i < len; ++i)
            {
                bufBlock[bufOff++] = in[inOff + i];
                if (bufOff == bufBlock.length)
                {
                    resultLen += decryptBlock(out, outOff + resultLen);
                }
            }
            return resultLen;
        }
    }

    private void initCipher()
    {
        if (cipherInitialized)
        {
            return;
        }

        // Pad AD to 16 bytes in MAC calculation
        mac.update(ZEROES, 0, pad16(aadSize));

        cipherInitialized = true;
    }

    /**
     * Calculates padding for a given input size to a 16 block boundary
     */
    private static int pad16(int dataSize)
    {
        return (16 - (dataSize & 0x0F)) & 0x0F;
    }

    public int doFinal(byte[] out, int outOff)
        throws IllegalStateException,
        InvalidCipherTextException
    {
        if (forEncryption)
        {
            if (out.length < (outOff + MAC_SIZE))
            {
                throw new OutputLengthException("Output buffer too short");
            }
            finaliseMac(out, outOff);
            reset(false);
            return MAC_SIZE;
        }
        else
        {
            int extra = bufOff;
            if (extra < MAC_SIZE)
            {
                throw new InvalidCipherTextException("Data too short - expected tag in input data");
            }
            extra -= MAC_SIZE;
            if (extra > 0)
            {
                if (out.length < (outOff + extra))
                {
                    throw new OutputLengthException("Output buffer too short");
                }
                mac.update(bufBlock, 0, extra);
                ctSize += extra;
                cipher.processBytes(bufBlock, 0, extra, out, outOff);
            }
            byte[] msgMac = new byte[MAC_SIZE];
            System.arraycopy(bufBlock, extra, msgMac, 0, MAC_SIZE);

            finaliseMac(macBlock, 0);
            if (!Arrays.constantTimeAreEqual(macBlock, msgMac))
            {
                throw new InvalidCipherTextException("mac check in " + getAlgorithmName() + " failed");
            }
            reset(false);
            return extra;
        }
    }

    private void finaliseMac(byte[] out, int outOff)
    {
        // Pad ciphertext to 16 bytes for MAC calculation
        mac.update(ZEROES, 0, pad16(ctSize));
        Pack.longToLittleEndian(aadSize, bufBlock, 0);
        Pack.longToLittleEndian(ctSize, bufBlock, 8);
        mac.update(bufBlock, 0, 16);
        mac.doFinal(out, outOff);
    }

    public byte[] getMac()
    {
        return macBlock;
    }

    public int getUpdateOutputSize(int len)
    {
        if (forEncryption)
        {
            return len;
        }
        else
        {
            int totalData = len + bufOff;
            if (totalData < MAC_SIZE)
            {
                return 0;
            }
            totalData -= MAC_SIZE;
            return totalData - (totalData % (bufBlock.length - MAC_SIZE));
        }
    }

    public int getOutputSize(int len)
    {

        if (forEncryption)
        {
            return len + MAC_SIZE;
        }
        else
        {
            int totalData = len + bufOff;
            return totalData < MAC_SIZE ? 0 : totalData - MAC_SIZE;
        }
    }

    public void reset()
    {
        reset(true);
    }

    private void reset(boolean clearMac)
    {
        // Set counter to 1 (skip first keystream block used in mac key gen)
        cipherInitialized = false;
        cipher.seekTo(BLOCK_SIZE);
        mac.reset();

        aadSize = 0;
        if (initialAssociatedText != null)
        {
            processAADBytes(initialAssociatedText, 0, initialAssociatedText.length);
        }

        ctSize = 0;
        bufOff = 0;
        Arrays.fill(bufBlock, (byte)0);

        if (clearMac)
        {
            Arrays.fill(macBlock, (byte)0);
        }
    }

}
