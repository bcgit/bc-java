package org.bouncycastle.crypto.engines;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Grain-128 AEAD, based on the current round 3 submission, https://grain-128aead.github.io/
 */
public class Grain128AEADEngine
    extends AEADBaseEngine
{
    /**
     * Constants
     */
    private static final int STATE_SIZE = 4;

    /**
     * Variables to hold the state of the engine during encryption and
     * decryption
     */
    private byte[] workingKey;
    private byte[] workingIV;
    private final int[] lfsr;
    private final int[] nfsr;
    private final int[] authAcc;
    private final int[] authSr;

    public Grain128AEADEngine()
    {
        algorithmName = "Grain-128 AEAD";
        KEY_SIZE = 16;
        IV_SIZE = 12;
        MAC_SIZE = 8;
        lfsr = new int[STATE_SIZE];
        nfsr = new int[STATE_SIZE];
        authAcc = new int[2];
        authSr = new int[2];
        setInnerMembers(ProcessingBufferType.Immediate, AADOperatorType.Stream, DataOperatorType.StreamCipher);
    }

    /**
     * Initialize a Grain-128AEAD cipher.
     */
    protected void init(byte[] key, byte[] iv)
        throws IllegalArgumentException
    {
        /*
         * Initialize variables.
         */
        workingIV = new byte[16];
        workingKey = key;
        System.arraycopy(iv, 0, workingIV, 0, IV_SIZE);
        workingIV[12] = (byte)0xFF;
        workingIV[13] = (byte)0xFF;
        workingIV[14] = (byte)0xFF;
        workingIV[15] = (byte)0x7F;
    }

    private void initGrain(int[] auth)
    {
        for (int quotient = 0; quotient < 2; ++quotient)
        {
            for (int remainder = 0; remainder < 32; ++remainder)
            {
                auth[quotient] |= getByteKeyStream() << remainder;
            }
        }
    }

    /**
     * Get output from non-linear function g(x).
     *
     * @return Output from NFSR.
     */
    private int getOutputNFSR()
    {
        int b0 = nfsr[0];
        int b3 = nfsr[0] >>> 3;
        int b11 = nfsr[0] >>> 11;
        int b13 = nfsr[0] >>> 13;
        int b17 = nfsr[0] >>> 17;
        int b18 = nfsr[0] >>> 18;
        int b22 = nfsr[0] >>> 22;
        int b24 = nfsr[0] >>> 24;
        int b25 = nfsr[0] >>> 25;
        int b26 = nfsr[0] >>> 26;
        int b27 = nfsr[0] >>> 27;
        int b40 = nfsr[1] >>> 8;
        int b48 = nfsr[1] >>> 16;
        int b56 = nfsr[1] >>> 24;
        int b59 = nfsr[1] >>> 27;
        int b61 = nfsr[1] >>> 29;
        int b65 = nfsr[2] >>> 1;
        int b67 = nfsr[2] >>> 3;
        int b68 = nfsr[2] >>> 4;
        int b70 = nfsr[2] >>> 6;
        int b78 = nfsr[2] >>> 14;
        int b82 = nfsr[2] >>> 18;
        int b84 = nfsr[2] >>> 20;
        int b88 = nfsr[2] >>> 24;
        int b91 = nfsr[2] >>> 27;
        int b92 = nfsr[2] >>> 28;
        int b93 = nfsr[2] >>> 29;
        int b95 = nfsr[2] >>> 31;
        int b96 = nfsr[3];

        return (b0 ^ b26 ^ b56 ^ b91 ^ b96 ^ b3 & b67 ^ b11 & b13 ^ b17 & b18
            ^ b27 & b59 ^ b40 & b48 ^ b61 & b65 ^ b68 & b84 ^ b22 & b24 & b25 ^ b70 & b78 & b82 ^ b88 & b92 & b93 & b95) & 1;
    }

    /**
     * Get output from linear function f(x).
     *
     * @return Output from LFSR.
     */
    private int getOutputLFSR()
    {
        int s0 = lfsr[0];
        int s7 = lfsr[0] >>> 7;
        int s38 = lfsr[1] >>> 6;
        int s70 = lfsr[2] >>> 6;
        int s81 = lfsr[2] >>> 17;
        int s96 = lfsr[3];

        return (s0 ^ s7 ^ s38 ^ s70 ^ s81 ^ s96) & 1;
    }

    /**
     * Get output from output function h(x).
     *
     * @return y_t.
     */
    private int getOutput()
    {
        int b2 = nfsr[0] >>> 2;
        int b12 = nfsr[0] >>> 12;
        int b15 = nfsr[0] >>> 15;
        int b36 = nfsr[1] >>> 4;
        int b45 = nfsr[1] >>> 13;
        int b64 = nfsr[2];
        int b73 = nfsr[2] >>> 9;
        int b89 = nfsr[2] >>> 25;
        int b95 = nfsr[2] >>> 31;
        int s8 = lfsr[0] >>> 8;
        int s13 = lfsr[0] >>> 13;
        int s20 = lfsr[0] >>> 20;
        int s42 = lfsr[1] >>> 10;
        int s60 = lfsr[1] >>> 28;
        int s79 = lfsr[2] >>> 15;
        int s93 = lfsr[2] >>> 29;
        int s94 = lfsr[2] >>> 30;

        return ((b12 & s8) ^ (s13 & s20) ^ (b95 & s42) ^ (s60 & s79) ^ (b12 & b95 & s94) ^ s93
            ^ b2 ^ b15 ^ b36 ^ b45 ^ b64 ^ b73 ^ b89) & 1;
    }

    /**
     * Shift array 1 bit and add val to index - 1.
     *
     * @param array The array to shift.
     * @param val   The value to shift in.
     */
    private void shift(int[] array, int val)
    {
        array[0] = (array[0] >>> 1) | (array[1] << 31);
        array[1] = (array[1] >>> 1) | (array[2] << 31);
        array[2] = (array[2] >>> 1) | (array[3] << 31);
        array[3] = (array[3] >>> 1) | (val << 31);
    }

    private void shift()
    {
        shift(nfsr, (getOutputNFSR() ^ lfsr[0]) & 1);
        shift(lfsr, (getOutputLFSR()) & 1);
    }

    protected void reset(boolean clearMac)
    {
        super.reset(clearMac);
        Pack.littleEndianToInt(workingKey, 0, nfsr);
        Pack.littleEndianToInt(workingIV, 0, lfsr);
        Arrays.clear(authAcc);
        Arrays.clear(authSr);
        int output;
        // 320 clocks initialization phase.
        for (int i = 0; i < 320; ++i)
        {
            output = getOutput();
            shift(nfsr, (getOutputNFSR() ^ lfsr[0] ^ output) & 1);
            shift(lfsr, (getOutputLFSR() ^ output) & 1);
        }
        for (int quotient = 0; quotient < 8; ++quotient)
        {
            for (int remainder = 0; remainder < 8; ++remainder)
            {
                output = getOutput();
                shift(nfsr, (getOutputNFSR() ^ lfsr[0] ^ output ^ ((workingKey[quotient]) >> remainder)) & 1);
                shift(lfsr, (getOutputLFSR() ^ output ^ ((workingKey[quotient + 8]) >> remainder)) & 1);
            }
        }
        initGrain(authAcc);
        initGrain(authSr);
    }

    private void updateInternalState(int mask)
    {
        mask = -mask;
        authAcc[0] ^= authSr[0] & mask;
        authAcc[1] ^= authSr[1] & mask;
        mask = getByteKeyStream();
        authSr[0] = (authSr[0] >>> 1) | (authSr[1] << 31);
        authSr[1] = (authSr[1] >>> 1) | (mask << 31);
    }

    public int getUpdateOutputSize(int len)
    {
        return getTotalBytesForUpdate(len);
    }

    @Override
    protected void finishAAD(State nextState, boolean isDoFinal)
    {
        finishAAD1(nextState);
    }

    @Override
    protected void processFinalBlock(byte[] output, int outOff)
    {
        authAcc[0] ^= authSr[0];
        authAcc[1] ^= authSr[1];
        Pack.intToLittleEndian(authAcc, mac, 0);
    }

    @Override
    protected void processBufferAAD(byte[] input, int inOff)
    {
    }

    @Override
    protected void processFinalAAD()
    {
        // Encode(ad length) denotes the message length encoded in the DER format.
        
        int len = aadOperator.getLen();
        byte[] input = ((StreamAADOperator)aadOperator).getBytes();

        // Need up to 5 bytes for the DER length as an 'int'
        byte[] ader = new byte[5];

        int pos;
        if (len < 128)
        {
            pos = ader.length - 1;
            ader[pos] = (byte)len;
        }
        else
        {
            pos = ader.length;

            int dl = len;
            do
            {
                ader[--pos] = (byte)dl;
                dl >>>= 8;
            }
            while (dl != 0);

            int count = ader.length - pos;
            ader[--pos] = (byte)(0x80 | count);
        }

        absorbAadData(ader, pos, ader.length - pos);
        absorbAadData(input, 0, len);
    }

    private void absorbAadData(byte[] buf, int off, int len)
    {
        for (int i = 0; i < len; ++i)
        {
            byte b = buf[off + i];
            for (int j = 0; j < 8; ++j)
            {
                shift();
                updateInternalState((b >> j) & 1);
            }
        }
    }

    private int getByteKeyStream()
    {
        int rlt = getOutput();
        shift();
        return rlt;
    }

    @Override
    protected void processBufferEncrypt(byte[] input, int inOff, byte[] output, int outOff)
    {
        int len = dataOperator.getLen();
        for (int i = 0; i < len; ++i)
        {
            byte cc = 0, input_i = input[inOff + i];
            for (int j = 0; j < 8; ++j)
            {
                int input_i_j = (input_i >> j) & 1;
                cc |= (input_i_j ^ getByteKeyStream()) << j;
                updateInternalState(input_i_j);
            }
            output[outOff + i] = cc;
        }
    }

    @Override
    protected void processBufferDecrypt(byte[] input, int inOff, byte[] output, int outOff)
    {
        int len = dataOperator.getLen();
        for (int i = 0; i < len; ++i)
        {
            byte cc = 0, input_i = input[inOff + i];
            for (int j = 0; j < 8; ++j)
            {
                cc |= (((input_i >> j) & 1) ^ getByteKeyStream()) << j;
                updateInternalState((cc >> j) & 1);
            }
            output[outOff + i] = cc;
        }
    }
}
