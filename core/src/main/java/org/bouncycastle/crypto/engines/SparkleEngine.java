package org.bouncycastle.crypto.engines;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Sparkle v1.2, based on the current round 3 submission, https://sparkle-lwc.github.io/
 * Reference C implementation: https://github.com/cryptolu/sparkle
 * Specification: https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
 */
public class SparkleEngine
    implements AEADBlockCipher
{
    public enum SparkleParameters
    {
        SCHWAEMM128_128,
        SCHWAEMM256_128,
        SCHWAEMM192_192,
        SCHWAEMM256_256
    }
    private final int[] state;
    private final int[] k;
    private final int[] npub;
    private final byte[] tag;
    private boolean encrypted;
    private boolean aadFinished;
    private final ByteArrayOutputStream aadData = new ByteArrayOutputStream();
    private final int SCHWAEMM_KEY_LEN;
    private final int SCHWAEMM_NONCE_LEN;
    private final int SPARKLE_STEPS_SLIM;
    private final int SPARKLE_STEPS_BIG;
    private final int KEY_WORDS;
    private final int TAG_WORDS;
    private final int TAG_BYTES;
    private final int STATE_BRANS;
    private final int STATE_WORDS;
    private final int RATE_WORDS;
    private final int RATE_BYTES;
    private final int CAP_WORDS;
    private final int _A0;
    private final int _A1;
    private final int _M2;
    private final int _M3;

    public SparkleEngine(SparkleParameters sparkleParameters)
    {
        int SPARKLE_STATE;
        int SCHWAEMM_TAG_LEN;
        int SPARKLE_CAPACITY;
        switch (sparkleParameters)
        {
        case SCHWAEMM128_128:
            SCHWAEMM_KEY_LEN = 128;
            SCHWAEMM_NONCE_LEN = 128;
            SCHWAEMM_TAG_LEN = 128;
            SPARKLE_STATE = 256;
            SPARKLE_CAPACITY = 128;
            SPARKLE_STEPS_SLIM = 7;
            SPARKLE_STEPS_BIG = 10;
            break;
        case SCHWAEMM256_128:
            SCHWAEMM_KEY_LEN = 128;
            SCHWAEMM_NONCE_LEN = 256;
            SCHWAEMM_TAG_LEN = 128;
            SPARKLE_STATE = 384;
            SPARKLE_CAPACITY = 128;
            SPARKLE_STEPS_SLIM = 7;
            SPARKLE_STEPS_BIG = 11;
            break;
        case SCHWAEMM192_192:
            SCHWAEMM_KEY_LEN = 192;
            SCHWAEMM_NONCE_LEN = 192;
            SCHWAEMM_TAG_LEN = 192;
            SPARKLE_STATE = 384;
            SPARKLE_CAPACITY = 192;
            SPARKLE_STEPS_SLIM = 7;
            SPARKLE_STEPS_BIG = 11;
            break;
        case SCHWAEMM256_256:
            SCHWAEMM_KEY_LEN = 256;
            SCHWAEMM_NONCE_LEN = 256;
            SCHWAEMM_TAG_LEN = 256;
            SPARKLE_STATE = 512;
            SPARKLE_CAPACITY = 256;
            SPARKLE_STEPS_SLIM = 8;
            SPARKLE_STEPS_BIG = 12;
            break;
        default:
            throw new IllegalArgumentException("Invalid definition of SCHWAEMM instance");
        }
        KEY_WORDS = SCHWAEMM_KEY_LEN >>> 5;
        TAG_WORDS = SCHWAEMM_TAG_LEN >>> 5;
        TAG_BYTES = SCHWAEMM_TAG_LEN >>> 3;
        STATE_BRANS = SPARKLE_STATE >>> 6;
        STATE_WORDS = SPARKLE_STATE >>> 5;
        RATE_WORDS = SCHWAEMM_NONCE_LEN >>> 5;
        RATE_BYTES = SCHWAEMM_NONCE_LEN >>> 3;
        int CAP_BRANS = SPARKLE_CAPACITY >>> 6;
        CAP_WORDS = SPARKLE_CAPACITY >>> 5;
        _A0 = ((((1 << CAP_BRANS))) << 24);
        _A1 = (((1 ^ (1 << CAP_BRANS))) << 24);
        _M2 = (((2 ^ (1 << CAP_BRANS))) << 24);
        _M3 = (((3 ^ (1 << CAP_BRANS))) << 24);
        state = new int[STATE_WORDS];
        tag = new byte[TAG_BYTES];
        k = new int[KEY_WORDS];
        npub = new int[RATE_WORDS];
    }

    private int ROT(int x, int n)
    {
        return (((x) >>> n) | ((x) << (32 - n)));
    }

    private int ELL(int x)
    {
        return ROT(((x) ^ ((x) << 16)), 16);
    }

    private static final int[] RCON = {0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738, 0xBB1185EB, 0x4F7C7B57,
        0xCFBFA1C8, 0xC2B3293D};

    void sparkle_opt(int[] state, int brans, int steps)
    {
        int i, j, rc, tmpx, tmpy, x0, y0;
        for (i = 0; i < steps; i++)
        {
            // Add round ant
            state[1] ^= RCON[i & 7];
            state[3] ^= i;
            // ARXBOX layer
            for (j = 0; j < 2 * brans; j += 2)
            {
                rc = RCON[j >>> 1];
                state[j] += ROT(state[j + 1], 31);
                state[j + 1] ^= ROT(state[j], 24);
                state[j] ^= rc;
                state[j] += ROT(state[j + 1], 17);
                state[j + 1] ^= ROT(state[j], 17);
                state[j] ^= rc;
                state[j] += state[j + 1];
                state[j + 1] ^= ROT(state[j], 31);
                state[j] ^= rc;
                state[j] += ROT(state[j + 1], 24);
                state[j + 1] ^= ROT(state[j], 16);
                state[j] ^= rc;
            }
            // Linear layer
            tmpx = x0 = state[0];
            tmpy = y0 = state[1];
            for (j = 2; j < brans; j += 2)
            {
                tmpx ^= state[j];
                tmpy ^= state[j + 1];
            }
            tmpx = ELL(tmpx);
            tmpy = ELL(tmpy);
            for (j = 2; j < brans; j += 2)
            {
                state[j - 2] = state[j + brans] ^ state[j] ^ tmpy;
                state[j + brans] = state[j];
                state[j - 1] = state[j + brans + 1] ^ state[j + 1] ^ tmpx;
                state[j + brans + 1] = state[j + 1];
            }
            state[brans - 2] = state[brans] ^ x0 ^ tmpy;
            state[brans] = x0;
            state[brans - 1] = state[brans + 1] ^ y0 ^ tmpx;
            state[brans + 1] = y0;
        }
    }

    private int CAP_INDEX(int i)
    {
        if (RATE_WORDS > CAP_WORDS)
        {
            return i & (CAP_WORDS - 1);
        }
        return i;
    }

    // The ProcessAssocData function absorbs the associated data, which becomes
    // only authenticated but not encrypted, into the state (in blocks of size
    // RATE_BYTES). Note that this function MUST NOT be called when the length of
    // the associated data is 0.
    void ProcessAssocData(int[] state, byte[] in, int inlen)
    {
        // Main Authentication Loop
        int inOff = 0, tmp, i, j;
        int[] in32 = Pack.littleEndianToInt(in, inOff, in.length >>> 2);
        while (inlen > RATE_BYTES)
        {
            // combined Rho and rate-whitening operation
            // Rho and rate-whitening for the authentication of associated data. The third
            // parameter indicates whether the uint8_t-pointer 'in' is properly aligned to
            // permit casting to a int-pointer. If this is the case then array 'in' is
            // processed directly, otherwise it is first copied to an aligned buffer.
            for (i = 0, j = RATE_WORDS / 2; i < RATE_WORDS / 2; i++, j++)
            {
                tmp = state[i];
                state[i] = state[j] ^ in32[i + (inOff >> 2)] ^ state[RATE_WORDS + i];
                state[j] ^= tmp ^ in32[j + (inOff >> 2)] ^ state[RATE_WORDS + CAP_INDEX(j)];
            }
            // execute SPARKLE with slim number of steps
            sparkle_opt(state, STATE_BRANS, SPARKLE_STEPS_SLIM);
            inlen -= RATE_BYTES;
            inOff += RATE_BYTES;
        }
        // Authentication of Last Block
        // addition of ant A0 or A1 to the state
        state[STATE_WORDS - 1] ^= ((inlen < RATE_BYTES) ? _A0 : _A1);
        // combined Rho and rate-whitening (incl. padding)
        // Rho and rate-whitening for the authentication of the last associated-data
        // block. Since this last block may require padding, it is always copied to a buffer.
        int[] buffer = new int[RATE_WORDS];
        for (i = 0; i < inlen; ++i)
        {
            buffer[i >>> 2] |= in[inOff++] << ((i & 3) << 3);
        }
        if (inlen < RATE_BYTES)
        {  // padding
            buffer[i >>> 2] |= 0x80 << ((i & 3) << 3);
        }
        for (i = 0, j = RATE_WORDS / 2; i < RATE_WORDS / 2; i++, j++)
        {
            tmp = state[i];
            state[i] = state[j] ^ buffer[i] ^ state[RATE_WORDS + i];
            state[j] ^= tmp ^ buffer[j] ^ state[RATE_WORDS + CAP_INDEX(j)];
        }
        // execute SPARKLE with big number of steps
        sparkle_opt(state, STATE_BRANS, SPARKLE_STEPS_BIG);
    }

    // The ProcessPlainText function encrypts the plaintext (input blocks of size
    // RATE_BYTES) and generates the respective ciphertext. The uint8_t-array 'input'
    // contains the plaintext and the ciphertext is written to uint8_t-array 'output'
    // ('input' and 'output' can be the same array, i.e. they can have the same start
    // address). Note that this function MUST NOT be called when the length of the
    // plaintext is 0.
    void ProcessPlainText(int[] state, byte[] output, byte[] input, int inOff, int inlen)
    {
        // Main Encryption Loop
        int outOff = 0, tmp1, tmp2, i, j;
        int[] in32 = Pack.littleEndianToInt(input, inOff, input.length >>> 2);
        int[] out32 = new int[output.length >>> 2];
        while (inlen > RATE_BYTES)
        {
            // combined Rho and rate-whitening operation
            // Rho and rate-whitening for the encryption of plaintext. The third parameter
            // indicates whether the uint8_t-pointers 'input' and 'output' are properly aligned
            // to permit casting to int-pointers. If this is the case then array 'input'
            // and 'output' are processed directly, otherwise 'input' is copied to an aligned buffer.
            for (i = 0, j = RATE_WORDS / 2; i < RATE_WORDS / 2; i++, j++)
            {
                tmp1 = state[i];
                tmp2 = state[j];
                state[i] = state[j] ^ in32[i + (inOff >> 2)] ^ state[RATE_WORDS + i];
                state[j] ^= tmp1 ^ in32[j + (inOff >> 2)] ^ state[RATE_WORDS + CAP_INDEX(j)];
                out32[i] = in32[i] ^ tmp1;
                out32[j] = in32[j] ^ tmp2;
            }
            Pack.intToLittleEndian(out32, 0, RATE_WORDS, output, outOff);
            // execute SPARKLE with slim number of steps
            sparkle_opt(state, STATE_BRANS, SPARKLE_STEPS_SLIM);
            inlen -= RATE_BYTES;
            outOff += RATE_BYTES;
            inOff += RATE_BYTES;
        }
        // Encryption of Last Block
        // addition of ant M2 or M3 to the state
        state[STATE_WORDS - 1] ^= ((inlen < RATE_BYTES) ? _M2 : _M3);
        // combined Rho and rate-whitening (incl. padding)
        // Rho and rate-whitening for the encryption of the last plaintext block. Since
        // this last block may require padding, it is always copied to a buffer.
        int[] buffer = new int[RATE_WORDS];
        for (i = 0; i < inlen; ++i)
        {
            buffer[i >>> 2] |= (input[inOff++] & 0xff) << ((i & 3) << 3);
        }
        if (inlen < RATE_BYTES)
        {  // padding
            buffer[i >>> 2] |= 0x80 << ((i & 3) << 3);
        }
        for (i = 0, j = RATE_WORDS / 2; i < RATE_WORDS / 2; i++, j++)
        {
            tmp1 = state[i];
            tmp2 = state[j];
            state[i] = state[j] ^ buffer[i] ^ state[RATE_WORDS + i];
            state[j] ^= tmp1 ^ buffer[j] ^ state[RATE_WORDS + CAP_INDEX(j)];
            buffer[i] ^= tmp1;
            buffer[j] ^= tmp2;
        }
        for (i = 0; i < inlen; ++i)
        {
            output[outOff++] = (byte)(buffer[i >>> 2] >>> ((i & 3) << 3));
        }
        // execute SPARKLE with big number of steps
        sparkle_opt(state, STATE_BRANS, SPARKLE_STEPS_BIG);
    }

    @Override
    public BlockCipher getUnderlyingCipher()
    {
        return null;
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        /**
         * Sparkle encryption and decryption is completely symmetrical, so the
         * 'forEncryption' is irrelevant.
         */
        if (!(params instanceof ParametersWithIV))
        {
            throw new IllegalArgumentException(
                "Sparkle init parameters must include an IV");
        }

        ParametersWithIV ivParams = (ParametersWithIV)params;
        byte[] iv = ivParams.getIV();

        if (iv == null || iv.length != SCHWAEMM_NONCE_LEN >> 3)
        {
            throw new IllegalArgumentException(
                "Sparkle requires exactly 16 bytes of IV");
        }
        Pack.littleEndianToInt(iv, 0, npub, 0, RATE_WORDS);

        if (!(ivParams.getParameters() instanceof KeyParameter))
        {
            throw new IllegalArgumentException(
                "Sparkle init parameters must include a key");
        }

        KeyParameter key = (KeyParameter)ivParams.getParameters();
        byte[] key8 = key.getKey();
        if (key8.length != SCHWAEMM_KEY_LEN >> 3)
        {
            throw new IllegalArgumentException("Sparkle key must be 128 bits long");
        }
        Pack.littleEndianToInt(key8, 0, k, 0, KEY_WORDS);

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(
            this.getAlgorithmName(), 128, params, Utils.getPurpose(forEncryption)));
        reset();
    }

    @Override
    public String getAlgorithmName()
    {
        return "Sparkle AEAD";
    }

    @Override
    public void processAADByte(byte input)
    {
        aadData.write(input);
    }

    @Override
    public void processAADBytes(byte[] input, int inOff, int len)
    {
        aadData.write(input, inOff, len);
    }

    @Override
    public int processByte(byte input, byte[] output, int outOff)
        throws DataLengthException
    {
        return processBytes(new byte[]{input}, 0, 1, output, outOff);
    }

    @Override
    public int processBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        throws DataLengthException
    {
        if (encrypted)
        {
            throw new IllegalArgumentException("Sparkle has processed encryption/decryption");
        }
        byte[] ad = aadData.toByteArray();
        int adsize = ad.length;
        if (adsize != 0)
        {
            ProcessAssocData(state, ad, adsize);
        }
        if (len != 0)
        {
            ProcessPlainText(state, output, input, inOff, len);
        }
        return len;
    }

    @Override
    public int doFinal(byte[] output, int outOff)
        throws IllegalStateException, InvalidCipherTextException
    {
        getMac();
        System.arraycopy(tag, 0, output, outOff, TAG_BYTES);
        reset(false);
        return TAG_BYTES;
    }

    @Override
    public byte[] getMac()
    {
        if (!aadFinished)
        {
            // the key to the capacity part of the state.
            int[] buffer = new int[TAG_WORDS];
            // to prevent (potentially) unaligned memory accesses
            System.arraycopy(k, 0, buffer, 0, KEY_WORDS);
            // add key to the capacity-part of the state
            for (int i = 0; i < KEY_WORDS; i++)
            {
                state[RATE_WORDS + i] ^= buffer[i];
            }
            aadFinished = true;
        }
        encrypted = true;
        Pack.intToLittleEndian(state, RATE_WORDS, TAG_WORDS, tag, 0);
        return tag;
    }

    @Override
    public int getUpdateOutputSize(int len)
    {
        return len;
    }

    @Override
    public int getOutputSize(int len)
    {
        return len + TAG_BYTES;
    }

    @Override
    public void reset()
    {
        reset(true);
    }

    private void reset(boolean clearMac)
    {
        if (clearMac)
        {
            Arrays.fill(tag, (byte)0);
        }
        // The Initialize function loads nonce and key into the state and executes the
        // SPARKLE permutation with the big number of steps.
        // load nonce into the rate-part of the state
        System.arraycopy(npub, 0, state, 0, RATE_WORDS);
        // load key into the capacity-part of the sate
        System.arraycopy(k, 0, state, RATE_WORDS, KEY_WORDS);
        // execute SPARKLE with big number of steps
        sparkle_opt(state, STATE_BRANS, SPARKLE_STEPS_BIG);
        aadData.reset();
        encrypted = false;
        aadFinished = false;
    }
}
