package org.bouncycastle.crypto.engines;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Elephant AEAD v2, based on the current round 3 submission, https://www.esat.kuleuven.be/cosic/elephant/
 * Reference C implementation: https://github.com/TimBeyne/Elephant
 * Specification: https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/elephant-spec-final.pdf
 */
public class ElephantEngine
    implements AEADCipher
{
    public enum ElephantParameters
    {
        elephant160,
        elephant176,
        elephant200
    }

    private enum State
    {
        Uninitialized,
        EncInit,
        EncAad, // can process AAD
        EncData, // cannot process AAD
        EncFinal,
        DecInit,
        DecAad, // can process AAD
        DecData, // cannot process AAD
        DecFinal,
    }

    private boolean forEncryption;
    private final String algorithmName;
    private final ElephantParameters parameters;
    private final int BLOCK_SIZE;
    private int nBits;
    private int nSBox;
    private final int nRounds;
    private byte lfsrIV;
    private byte[] tag;
    private byte[] npub;
    private byte[] expanded_key;
    private final byte CRYPTO_KEYBYTES = 16;
    private final byte CRYPTO_NPUBBYTES = 12;
    private final byte CRYPTO_ABYTES;
    private boolean initialised;
    private int nb_its;
    private byte[] ad;
    private int adOff;
    private int adlen;
    private final byte[] tag_buffer;
    private byte[] previous_mask;
    private byte[] current_mask;
    private byte[] next_mask;
    private final byte[] buffer;
    private State m_state = State.Uninitialized;
    private final ByteArrayOutputStream aadData = new ByteArrayOutputStream();
    private int inputOff;
    private byte[] inputMessage;
    private final byte[] previous_outputMessage;
    private final byte[] outputMessage;

    private final byte[] sBoxLayer = {
        (byte)0xee, (byte)0xed, (byte)0xeb, (byte)0xe0, (byte)0xe2, (byte)0xe1, (byte)0xe4, (byte)0xef, (byte)0xe7, (byte)0xea, (byte)0xe8, (byte)0xe5, (byte)0xe9, (byte)0xec, (byte)0xe3, (byte)0xe6,
        (byte)0xde, (byte)0xdd, (byte)0xdb, (byte)0xd0, (byte)0xd2, (byte)0xd1, (byte)0xd4, (byte)0xdf, (byte)0xd7, (byte)0xda, (byte)0xd8, (byte)0xd5, (byte)0xd9, (byte)0xdc, (byte)0xd3, (byte)0xd6,
        (byte)0xbe, (byte)0xbd, (byte)0xbb, (byte)0xb0, (byte)0xb2, (byte)0xb1, (byte)0xb4, (byte)0xbf, (byte)0xb7, (byte)0xba, (byte)0xb8, (byte)0xb5, (byte)0xb9, (byte)0xbc, (byte)0xb3, (byte)0xb6,
        (byte)0x0e, (byte)0x0d, (byte)0x0b, (byte)0x00, (byte)0x02, (byte)0x01, (byte)0x04, (byte)0x0f, (byte)0x07, (byte)0x0a, (byte)0x08, (byte)0x05, (byte)0x09, (byte)0x0c, (byte)0x03, (byte)0x06,
        (byte)0x2e, (byte)0x2d, (byte)0x2b, (byte)0x20, (byte)0x22, (byte)0x21, (byte)0x24, (byte)0x2f, (byte)0x27, (byte)0x2a, (byte)0x28, (byte)0x25, (byte)0x29, (byte)0x2c, (byte)0x23, (byte)0x26,
        (byte)0x1e, (byte)0x1d, (byte)0x1b, (byte)0x10, (byte)0x12, (byte)0x11, (byte)0x14, (byte)0x1f, (byte)0x17, (byte)0x1a, (byte)0x18, (byte)0x15, (byte)0x19, (byte)0x1c, (byte)0x13, (byte)0x16,
        (byte)0x4e, (byte)0x4d, (byte)0x4b, (byte)0x40, (byte)0x42, (byte)0x41, (byte)0x44, (byte)0x4f, (byte)0x47, (byte)0x4a, (byte)0x48, (byte)0x45, (byte)0x49, (byte)0x4c, (byte)0x43, (byte)0x46,
        (byte)0xfe, (byte)0xfd, (byte)0xfb, (byte)0xf0, (byte)0xf2, (byte)0xf1, (byte)0xf4, (byte)0xff, (byte)0xf7, (byte)0xfa, (byte)0xf8, (byte)0xf5, (byte)0xf9, (byte)0xfc, (byte)0xf3, (byte)0xf6,
        (byte)0x7e, (byte)0x7d, (byte)0x7b, (byte)0x70, (byte)0x72, (byte)0x71, (byte)0x74, (byte)0x7f, (byte)0x77, (byte)0x7a, (byte)0x78, (byte)0x75, (byte)0x79, (byte)0x7c, (byte)0x73, (byte)0x76,
        (byte)0xae, (byte)0xad, (byte)0xab, (byte)0xa0, (byte)0xa2, (byte)0xa1, (byte)0xa4, (byte)0xaf, (byte)0xa7, (byte)0xaa, (byte)0xa8, (byte)0xa5, (byte)0xa9, (byte)0xac, (byte)0xa3, (byte)0xa6,
        (byte)0x8e, (byte)0x8d, (byte)0x8b, (byte)0x80, (byte)0x82, (byte)0x81, (byte)0x84, (byte)0x8f, (byte)0x87, (byte)0x8a, (byte)0x88, (byte)0x85, (byte)0x89, (byte)0x8c, (byte)0x83, (byte)0x86,
        (byte)0x5e, (byte)0x5d, (byte)0x5b, (byte)0x50, (byte)0x52, (byte)0x51, (byte)0x54, (byte)0x5f, (byte)0x57, (byte)0x5a, (byte)0x58, (byte)0x55, (byte)0x59, (byte)0x5c, (byte)0x53, (byte)0x56,
        (byte)0x9e, (byte)0x9d, (byte)0x9b, (byte)0x90, (byte)0x92, (byte)0x91, (byte)0x94, (byte)0x9f, (byte)0x97, (byte)0x9a, (byte)0x98, (byte)0x95, (byte)0x99, (byte)0x9c, (byte)0x93, (byte)0x96,
        (byte)0xce, (byte)0xcd, (byte)0xcb, (byte)0xc0, (byte)0xc2, (byte)0xc1, (byte)0xc4, (byte)0xcf, (byte)0xc7, (byte)0xca, (byte)0xc8, (byte)0xc5, (byte)0xc9, (byte)0xcc, (byte)0xc3, (byte)0xc6,
        (byte)0x3e, (byte)0x3d, (byte)0x3b, (byte)0x30, (byte)0x32, (byte)0x31, (byte)0x34, (byte)0x3f, (byte)0x37, (byte)0x3a, (byte)0x38, (byte)0x35, (byte)0x39, (byte)0x3c, (byte)0x33, (byte)0x36,
        (byte)0x6e, (byte)0x6d, (byte)0x6b, (byte)0x60, (byte)0x62, (byte)0x61, (byte)0x64, (byte)0x6f, (byte)0x67, (byte)0x6a, (byte)0x68, (byte)0x65, (byte)0x69, (byte)0x6c, (byte)0x63, (byte)0x66
    };

    private final byte[] KeccakRoundConstants = {
        (byte)0x01, (byte)0x82, (byte)0x8a, (byte)0x00, (byte)0x8b, (byte)0x01, (byte)0x81, (byte)0x09, (byte)0x8a,
        (byte)0x88, (byte)0x09, (byte)0x0a, (byte)0x8b, (byte)0x8b, (byte)0x89, (byte)0x03, (byte)0x02, (byte)0x80
    };

    private final int[] KeccakRhoOffsets = {0, 1, 6, 4, 3, 4, 4, 6, 7, 4, 3, 2, 3, 1, 7, 1, 5, 7, 5, 0, 2, 2, 5, 0, 6};

    public ElephantEngine(ElephantParameters parameters)
    {
        switch (parameters)
        {
        case elephant160:
            BLOCK_SIZE = 20;
            nBits = 160;
            nSBox = 20;
            nRounds = 80;
            lfsrIV = 0x75;
            CRYPTO_ABYTES = 8;
            algorithmName = "Elephant 160 AEAD";
            break;
        case elephant176:
            BLOCK_SIZE = 22;
            nBits = 176;
            nSBox = 22;
            nRounds = 90;
            lfsrIV = 0x45;
            CRYPTO_ABYTES = 8;
            algorithmName = "Elephant 176 AEAD";
            break;
        case elephant200:
            BLOCK_SIZE = 25;
            nRounds = 18;
            CRYPTO_ABYTES = 16;
            algorithmName = "Elephant 200 AEAD";
            break;
        default:
            throw new IllegalArgumentException("Invalid parameter settings for Elephant");
        }
        this.parameters = parameters;
        tag_buffer = new byte[BLOCK_SIZE];
        previous_mask = new byte[BLOCK_SIZE];
        current_mask = new byte[BLOCK_SIZE];
        next_mask = new byte[BLOCK_SIZE];
        buffer = new byte[BLOCK_SIZE];
        previous_outputMessage = new byte[BLOCK_SIZE];
        outputMessage = new byte[BLOCK_SIZE];
        initialised = false;
        reset(false);
    }

    private void permutation(byte[] state)
    {
        switch (parameters)
        {
        case elephant160:
        case elephant176:
            byte IV = lfsrIV;
            byte[] tmp = new byte[nSBox];
            for (int i = 0; i < nRounds; i++)
            {
                /* Add counter values */
                state[0] ^= IV;
                state[nSBox - 1] ^= (byte)(((IV & 0x01) << 7) | ((IV & 0x02) << 5) | ((IV & 0x04) << 3) | ((IV & 0x08)
                    << 1) | ((IV & 0x10) >>> 1) | ((IV & 0x20) >>> 3) | ((IV & 0x40) >>> 5) | ((IV & 0x80) >>> 7));
                IV = (byte)(((IV << 1) | (((0x40 & IV) >>> 6) ^ ((0x20 & IV) >>> 5))) & 0x7f);
                /* sBoxLayer layer */
                for (int j = 0; j < nSBox; j++)
                {
                    state[j] = sBoxLayer[(state[j] & 0xFF)];
                }
                /* pLayer */
                int PermutedBitNo;
                Arrays.fill(tmp, (byte)0);
                for (int j = 0; j < nSBox; j++)
                {
                    for (int k = 0; k < 8; k++)
                    {
                        PermutedBitNo = (j << 3) + k;
                        if (PermutedBitNo != nBits - 1)
                        {
                            PermutedBitNo = ((PermutedBitNo * nBits) >> 2) % (nBits - 1);
                        }
                        tmp[PermutedBitNo >>> 3] ^= (((state[j] & 0xFF) >>> k) & 0x1) << (PermutedBitNo & 7);
                    }
                }
                System.arraycopy(tmp, 0, state, 0, nSBox);
            }
            break;
        case elephant200:
            for (int i = 0; i < nRounds; i++)
            {
                KeccakP200Round(state, i);
            }
            break;
        }
    }

    private byte rotl(byte b)
    {
        return (byte)(((b & 0xFF) << 1) | ((b & 0xFF) >>> 7));
    }

    private byte ROL8(byte a, int offset)
    {
        return (byte)((offset != 0) ? (((a & 0xFF) << offset) ^ ((a & 0xFF) >>> (8 - offset))) : a);
    }

    private int index(int x, int y)
    {
        return x + y * 5;
    }

    private void KeccakP200Round(byte[] state, int indexRound)
    {
        int x, y;
        byte[] tempA = new byte[25];
        //theta
        for (x = 0; x < 5; x++)
        {
            for (y = 0; y < 5; y++)
            {
                tempA[x] ^= state[index(x, y)];
            }
        }
        for (x = 0; x < 5; x++)
        {
            tempA[x + 5] = (byte)(ROL8(tempA[(x + 1) % 5], 1) ^ tempA[(x + 4) % 5]);
        }
        for (x = 0; x < 5; x++)
        {
            for (y = 0; y < 5; y++)
            {
                state[index(x, y)] ^= tempA[x + 5];
            }
        }
        //rho
        for (x = 0; x < 5; x++)
        {
            for (y = 0; y < 5; y++)
            {
                tempA[index(x, y)] = ROL8(state[index(x, y)], KeccakRhoOffsets[index(x, y)]);
            }
        }
        //pi
        for (x = 0; x < 5; x++)
        {
            for (y = 0; y < 5; y++)
            {
                state[index(y, (2 * x + 3 * y) % 5)] = tempA[index(x, y)];
            }
        }
        //chi
        for (y = 0; y < 5; y++)
        {
            for (x = 0; x < 5; x++)
            {
                tempA[x] = (byte)(state[index(x, y)] ^ ((~state[index((x + 1) % 5, y)]) & state[index((x + 2) % 5, y)]));
            }
            for (x = 0; x < 5; x++)
            {
                state[index(x, y)] = tempA[x];
            }
        }
        //iota
        state[0] ^= KeccakRoundConstants[indexRound];//index(0,0)
    }


    // State should be BLOCK_SIZE bytes long
    // Note: input may be equal to output
    private void lfsr_step(byte[] output, byte[] input)
    {
        switch (parameters)
        {
        case elephant160:
            output[BLOCK_SIZE - 1] = (byte)((((input[0] & 0xFF) << 3) | ((input[0] & 0xFF) >>> 5)) ^
                ((input[3] & 0xFF) << 7) ^ ((input[13] & 0xFF) >>> 7));
            break;
        case elephant176:
            output[BLOCK_SIZE - 1] = (byte)(rotl(input[0]) ^ ((input[3] & 0xFF) << 7) ^ ((input[19] & 0xFF) >>> 7));
            break;
        case elephant200:
            output[BLOCK_SIZE - 1] = (byte)(rotl(input[0]) ^ rotl(input[2]) ^ (input[13] << 1));
            break;
        }
        System.arraycopy(input, 1, output, 0, BLOCK_SIZE - 1);
    }

    private void xor_block(byte[] state, byte[] block, int bOff, int size)
    {
        for (int i = 0; i < size; ++i)
        {
            state[i] ^= block[i + bOff];
        }
    }

    // Return the ith ciphertext block.
    // clen is the length of the ciphertext in bytes
    private void get_c_block(byte[] output, byte[] c, int cOff, int clen, int i)
    {
        int block_offset = i * BLOCK_SIZE;
        // If clen is divisible by BLOCK_SIZE, add an additional padding block
        if (block_offset == clen)
        {
            Arrays.fill(output, 0, BLOCK_SIZE, (byte)0);
            output[0] = 0x01;
            return;
        }
        int r_clen = clen - block_offset;
        // Fill with ciphertext if available
        if (BLOCK_SIZE <= r_clen)
        { // enough ciphertext
            System.arraycopy(c, cOff, output, 0, BLOCK_SIZE);
        }
        else
        { // not enough ciphertext, need to pad
            if (r_clen > 0) // c might be nullptr
            {
                System.arraycopy(c, cOff, output, 0, r_clen);
            }
            Arrays.fill(output, r_clen, BLOCK_SIZE, (byte)0);
            output[r_clen] = 0x01;
        }
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        this.forEncryption = forEncryption;
        if (!(params instanceof ParametersWithIV))
        {
            throw new IllegalArgumentException(algorithmName + " init parameters must include an IV");
        }
        ParametersWithIV ivParams = (ParametersWithIV)params;
        npub = ivParams.getIV();
        if (npub == null || npub.length != CRYPTO_NPUBBYTES)
        {
            throw new IllegalArgumentException(algorithmName + " requires exactly 12 bytes of IV");
        }
        if (!(ivParams.getParameters() instanceof KeyParameter))
        {
            throw new IllegalArgumentException(algorithmName + " init parameters must include a key");
        }
        KeyParameter key = (KeyParameter)ivParams.getParameters();
        byte[] k = key.getKey();
        if (k.length != CRYPTO_KEYBYTES)
        {
            throw new IllegalArgumentException(algorithmName + " key must be 128 bits long");
        }
        // Storage for the expanded key L
        expanded_key = new byte[BLOCK_SIZE];
        System.arraycopy(k, 0, expanded_key, 0, CRYPTO_KEYBYTES);
        permutation(expanded_key);
        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(
            this.getAlgorithmName(), 128, params, Utils.getPurpose(forEncryption)));
        initialised = true;
        m_state = forEncryption ? State.EncInit : State.DecInit;
        inputMessage = new byte[BLOCK_SIZE + (forEncryption ? 0 : CRYPTO_ABYTES)];
        reset(false);
    }

    @Override
    public String getAlgorithmName()
    {
        return algorithmName;
    }

    @Override
    public void processAADByte(byte input)
    {
        aadData.write(input);
    }

    @Override
    public void processAADBytes(byte[] input, int inOff, int len)
    {
        if (inOff + len > input.length)
        {
            throw new DataLengthException("input buffer too short");
        }
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
        if (inOff + len > input.length)
        {
            throw new DataLengthException("input buffer too short");
        }
        byte[] ad = aadData.toByteArray();


        if (inputOff + len - (forEncryption ? 0 : CRYPTO_ABYTES) >= BLOCK_SIZE)
        {
            switch (m_state)
            {
            case EncInit:
            case DecInit:
                processAADBytes(tag_buffer);
                break;
            }
            int mlen = inputOff + len - (forEncryption ? 0 : CRYPTO_ABYTES);
            int adlen = ad.length;
            int nblocks_c = mlen / BLOCK_SIZE;
            int nblocks_m = 1 + ((mlen % BLOCK_SIZE) != 0 ? nblocks_c : nblocks_c - 1);
            int nblocks_ad = 1 + (CRYPTO_NPUBBYTES + adlen) / BLOCK_SIZE;
            byte[] tempInput = new byte[Math.max(nblocks_c, 1) * BLOCK_SIZE];
            System.arraycopy(inputMessage, 0, tempInput, 0, inputOff);
            int templen = tempInput.length - inputOff;
            System.arraycopy(input, inOff, tempInput, inputOff, tempInput.length - inputOff);
            processBytes(tempInput, output, outOff, nblocks_c, nblocks_m, nblocks_c, mlen, nblocks_ad);
            inputOff = len - templen;
            System.arraycopy(input, inOff + templen, inputMessage, 0, inputOff);
            nb_its += nblocks_c;
            return nblocks_c * BLOCK_SIZE;
        }
        else
        {
            System.arraycopy(input, inOff, inputMessage, inputOff, len);
            inputOff += len;
            return 0;
        }
    }

    @Override
    public int doFinal(byte[] output, int outOff)
        throws IllegalStateException, InvalidCipherTextException
    {
        if (!initialised)
        {
            throw new IllegalArgumentException(algorithmName + " needs call init function before doFinal");
        }
        int len = inputOff;
        if ((forEncryption && len + outOff + CRYPTO_ABYTES > output.length) ||
            (!forEncryption && len + outOff - CRYPTO_ABYTES > output.length))
        {
            throw new OutputLengthException("output buffer is too short");
        }
        byte[] ad = aadData.toByteArray();
        switch (m_state)
        {
        case EncInit:
        case DecInit:
            processAADBytes(tag_buffer);
            break;
        }
        int mlen = len + nb_its * BLOCK_SIZE - (forEncryption ? 0 : CRYPTO_ABYTES);
        int adlen = ad.length;
        int nblocks_c = 1 + mlen / BLOCK_SIZE;
        int nblocks_m = (mlen % BLOCK_SIZE) != 0 ? nblocks_c : nblocks_c - 1;
        int nblocks_ad = 1 + (CRYPTO_NPUBBYTES + adlen) / BLOCK_SIZE;
        int nb_it = Math.max(nblocks_c + 1, nblocks_ad - 1);
        outOff += processBytes(inputMessage, output, outOff, nb_it, nblocks_m, nblocks_c, mlen, nblocks_ad);
        tag = new byte[CRYPTO_ABYTES];
        xor_block(tag_buffer, expanded_key, 0, BLOCK_SIZE);
        permutation(tag_buffer);
        xor_block(tag_buffer, expanded_key, 0, BLOCK_SIZE);
        if (forEncryption)
        {
            System.arraycopy(tag_buffer, 0, tag, 0, CRYPTO_ABYTES);
            System.arraycopy(tag, 0, output, outOff, tag.length);
            mlen += CRYPTO_ABYTES;
        }
        else
        {
            inputOff -= CRYPTO_ABYTES;
            for (int i = 0; i < CRYPTO_ABYTES; ++i)
            {
                if (tag_buffer[i] != inputMessage[inputOff + i])
                {
                    throw new IllegalArgumentException("Mac does not match");
                }
            }
        }
        reset(false);
        return mlen;
    }

    @Override
    public byte[] getMac()
    {
        return tag;
    }

    @Override
    public int getUpdateOutputSize(int len)
    {
        switch (m_state)
        {
        case Uninitialized:
            throw new IllegalArgumentException(algorithmName + " needs call init function before getUpdateOutputSize");
        case DecFinal:
        case EncFinal:
            return 0;
        case EncAad:
        case EncData:
        case EncInit:
            return inputOff + len + CRYPTO_ABYTES;
        }
        return Math.max(0, len + inputOff - CRYPTO_ABYTES);
    }

    @Override
    public int getOutputSize(int len)
    {
        switch (m_state)
        {
        case Uninitialized:
            throw new IllegalArgumentException(algorithmName + " needs call init function before getUpdateOutputSize");
        case DecFinal:
        case EncFinal:
            return 0;
        case EncAad:
        case EncData:
        case EncInit:
            return len + CRYPTO_ABYTES;
        }
        return Math.max(0, len - CRYPTO_ABYTES);
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
            tag = null;
        }
        aadData.reset();
        Arrays.fill(tag_buffer, (byte)0);
        inputOff = 0;
        nb_its = 0;
        adOff = -1;
    }

    public int getKeyBytesSize()
    {
        return CRYPTO_KEYBYTES;
    }

    public int getIVBytesSize()
    {
        return CRYPTO_NPUBBYTES;
    }

    public int getBlockSize()
    {
        return CRYPTO_ABYTES;
    }

    private void checkAad()
    {
        switch (m_state)
        {
        case DecData:
            throw new IllegalArgumentException(algorithmName + " cannot process AAD when the length of the plaintext to be processed exceeds the a block size");
        case EncData:
            throw new IllegalArgumentException(algorithmName + " cannot process AAD when the length of the ciphertext to be processed exceeds the a block size");
        case EncFinal:
            throw new IllegalArgumentException(algorithmName + " cannot be reused for encryption");
        default:
            break;
        }
    }

    private void processAADBytes(byte[] output)
    {
        checkAad();

        if (adOff == -1)
        {
            adlen = aadData.size();
            ad = aadData.toByteArray();
            adOff = 0;
        }
        int len = 0;
        switch (m_state)
        {
        case DecInit:
            System.arraycopy(expanded_key, 0, current_mask, 0, BLOCK_SIZE);
            System.arraycopy(npub, 0, output, 0, CRYPTO_NPUBBYTES);
            len += CRYPTO_NPUBBYTES;
            m_state = State.DecAad;
            break;
        case EncInit:
            System.arraycopy(expanded_key, 0, current_mask, 0, BLOCK_SIZE);
            System.arraycopy(npub, 0, output, 0, CRYPTO_NPUBBYTES);
            len += CRYPTO_NPUBBYTES;
            m_state = State.EncAad;
            break;
        case DecAad:
        case EncAad:
            // If adlen is divisible by BLOCK_SIZE, add an additional padding block
            if (adOff == adlen)
            {
                Arrays.fill(output, 0, BLOCK_SIZE, (byte)0);
                output[0] = 0x01;
                return;
            }
            break;
        case DecData:
            throw new IllegalArgumentException(algorithmName + " cannot process AAD when the length of the plaintext to be processed exceeds the a block size");
        case EncData:
            throw new IllegalArgumentException(algorithmName + " cannot process AAD when the length of the ciphertext to be processed exceeds the a block size");
        case EncFinal:
            throw new IllegalArgumentException(algorithmName + " cannot be reused for encryption");
        }
        int r_outlen = BLOCK_SIZE - len;
        int r_adlen = adlen - adOff;
        // Fill with associated data if available
        if (r_outlen <= r_adlen)
        { // enough AD
            System.arraycopy(ad, adOff, output, len, r_outlen);
            adOff += r_outlen;
        }
        else
        { // not enough AD, need to pad
            if (r_adlen > 0) // ad might be nullptr
            {
                System.arraycopy(ad, adOff, output, len, r_adlen);
                adOff += r_adlen;
            }
            Arrays.fill(output, len + r_adlen, len + r_outlen, (byte)0);
            output[len + r_adlen] = 0x01;
            switch (m_state)
            {
            case DecAad:
                m_state = State.DecData;
                break;
            case EncAad:
                m_state = State.EncData;
                break;
            }
        }
    }

    private int processBytes(byte[] m, byte[] output, int outOff, int nb_it, int nblocks_m, int nblocks_c, int mlen,
                             int nblocks_ad)
    {
        int rv = 0;
        for (int i = nb_its; i < nb_it; ++i)
        {
            // Compute mask for the next message
            lfsr_step(next_mask, current_mask);
            if (i < nblocks_m)
            {
                // Compute ciphertext block
                System.arraycopy(npub, 0, buffer, 0, CRYPTO_NPUBBYTES);
                Arrays.fill(buffer, CRYPTO_NPUBBYTES, BLOCK_SIZE, (byte)0);
                xor_block(buffer, current_mask, 0, BLOCK_SIZE);
                xor_block(buffer, next_mask, 0, BLOCK_SIZE);
                permutation(buffer);
                xor_block(buffer, current_mask, 0, BLOCK_SIZE);
                xor_block(buffer, next_mask, 0, BLOCK_SIZE);
                int r_size = (i == nblocks_m - 1) ? mlen - i * BLOCK_SIZE : BLOCK_SIZE;
                xor_block(buffer, m, 0, r_size);
                System.arraycopy(buffer, 0, output, outOff, r_size);
                if (forEncryption)
                {
                    System.arraycopy(buffer, 0, outputMessage, 0, r_size);
                }
                else
                {
                    System.arraycopy(m, 0, outputMessage, 0, r_size);
                }
                rv += r_size;
            }
            if (i > 0 && i <= nblocks_c)
            {
                // Compute tag for ciphertext block
                get_c_block(buffer, previous_outputMessage, 0, mlen, i - 1);
                xor_block(buffer, previous_mask, 0, BLOCK_SIZE);
                xor_block(buffer, next_mask, 0, BLOCK_SIZE);
                permutation(buffer);
                xor_block(buffer, previous_mask, 0, BLOCK_SIZE);
                xor_block(buffer, next_mask, 0, BLOCK_SIZE);
                xor_block(tag_buffer, buffer, 0, BLOCK_SIZE);
            }
            // If there is any AD left, compute tag for AD block
            if (i + 1 < nblocks_ad)
            {
                processAADBytes(buffer);
                xor_block(buffer, next_mask, 0, BLOCK_SIZE);
                permutation(buffer);
                xor_block(buffer, next_mask, 0, BLOCK_SIZE);
                xor_block(tag_buffer, buffer, 0, BLOCK_SIZE);
            }
            // Cyclically shift the mask buffers
            // Value of next_mask will be computed in the next iteration
            byte[] temp = previous_mask;
            previous_mask = current_mask;
            current_mask = next_mask;
            next_mask = temp;
            System.arraycopy(outputMessage, 0, previous_outputMessage, 0, BLOCK_SIZE);
        }
        return rv;
    }
}
