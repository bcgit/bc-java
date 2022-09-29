package org.bouncycastle.crypto.engines;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Pack;

/**
 * Grain-128 AEAD, based on the current round 3 submission, https://grain-128aead.github.io/
 */
public class Grain128AEADEngine
    implements AEADCipher
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
    private int[] lfsr;
    private int[] nfsr;
    private int[] authAcc;
    private int[] authSr;

    private boolean initialised = false;
    private boolean aadFinished = false;
    private ErasableOutputStream aadData = new ErasableOutputStream();

    private byte[] mac;

    public String getAlgorithmName()
    {
        return "Grain-128AEAD";
    }

    /**
     * Initialize a Grain-128AEAD cipher.
     *
     * @param forEncryption Whether or not we are for encryption.
     * @param params        The parameters required to set up the cipher.
     * @throws IllegalArgumentException If the params argument is inappropriate.
     */
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        /**
         * Grain encryption and decryption is completely symmetrical, so the
         * 'forEncryption' is irrelevant.
         */
        if (!(params instanceof ParametersWithIV))
        {
            throw new IllegalArgumentException(
                "Grain-128AEAD init parameters must include an IV");
        }

        ParametersWithIV ivParams = (ParametersWithIV)params;

        byte[] iv = ivParams.getIV();

        if (iv == null || iv.length != 12)
        {
            throw new IllegalArgumentException(
                "Grain-128AEAD requires exactly 12 bytes of IV");
        }

        if (!(ivParams.getParameters() instanceof KeyParameter))
        {
            throw new IllegalArgumentException(
                "Grain-128AEAD init parameters must include a key");
        }

        KeyParameter key = (KeyParameter)ivParams.getParameters();
        byte[] keyBytes = key.getKey();
        if (keyBytes.length != 16)
        {
            throw new IllegalArgumentException(
                "Grain-128AEAD key must be 128 bits long");
        }

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(
            this.getAlgorithmName(), 128, params, Utils.getPurpose(forEncryption)));

        /**
         * Initialize variables.
         */
        workingIV = new byte[16];
        workingKey = new byte[16];
        lfsr = new int[STATE_SIZE];
        nfsr = new int[STATE_SIZE];
        authAcc = new int[2];
        authSr = new int[2];

        System.arraycopy(iv, 0, workingIV, 0, iv.length);
        System.arraycopy(keyBytes, 0, workingKey, 0, keyBytes.length);

        reset();
    }

    /**
     * 320 clocks initialization phase.
     */
    private void initGrain()
    {
        for (int i = 0; i < 320; ++i)
        {
            int output = getOutput();
            nfsr = shift(nfsr, (getOutputNFSR() ^ lfsr[0] ^ output) & 1);
            lfsr = shift(lfsr, (getOutputLFSR() ^ output) & 1);
        }
        for (int quotient = 0; quotient < 8; ++quotient)
        {
            for (int remainder = 0; remainder < 8; ++remainder)
            {
                int output = getOutput();
                nfsr = shift(nfsr, (getOutputNFSR() ^ lfsr[0] ^ output ^ ((workingKey[quotient]) >> remainder)) & 1);
                lfsr = shift(lfsr, (getOutputLFSR() ^ output ^ ((workingKey[quotient + 8]) >> remainder)) & 1);
            }
        }
        for (int quotient = 0; quotient < 2; ++quotient)
        {
            for (int remainder = 0; remainder < 32; ++remainder)
            {
                int output = getOutput();
                nfsr = shift(nfsr, (getOutputNFSR() ^ lfsr[0]) & 1);
                lfsr = shift(lfsr, (getOutputLFSR()) & 1);
                authAcc[quotient] |= output << remainder;
            }
        }
        for (int quotient = 0; quotient < 2; ++quotient)
        {
            for (int remainder = 0; remainder < 32; ++remainder)
            {
                int output = getOutput();
                nfsr = shift(nfsr, (getOutputNFSR() ^ lfsr[0]) & 1);
                lfsr = shift(lfsr, (getOutputLFSR()) & 1);
                authSr[quotient] |= output << remainder;
            }
        }
        initialised = true;
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
     * Shift array 1 bit and add val to index.length - 1.
     *
     * @param array The array to shift.
     * @param val   The value to shift in.
     * @return The shifted array with val added to index.length - 1.
     */
    private int[] shift(int[] array, int val)
    {
        array[0] = (array[0] >>> 1) | (array[1] << 31);
        array[1] = (array[1] >>> 1) | (array[2] << 31);
        array[2] = (array[2] >>> 1) | (array[3] << 31);
        array[3] = (array[3] >>> 1) | (val << 31);
        return array;
    }

    /**
     * Set keys, reset cipher.
     *
     * @param keyBytes The key.
     * @param ivBytes  The IV.
     */
    private void setKey(byte[] keyBytes, byte[] ivBytes)
    {
        ivBytes[12] = (byte)0xFF;
        ivBytes[13] = (byte)0xFF;
        ivBytes[14] = (byte)0xFF;
        ivBytes[15] = (byte)0x7F;
        workingKey = keyBytes;
        workingIV = ivBytes;

        /**
         * Load NFSR and LFSR
         */
        Pack.littleEndianToInt(workingKey, 0, nfsr);
        Pack.littleEndianToInt(workingIV, 0, lfsr);
    }

    public int processBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        throws DataLengthException
    {
        if (!initialised)
        {
            throw new IllegalStateException(getAlgorithmName() + " not initialised");
        }

        if (!aadFinished)
        {
            doProcessAADBytes(aadData.getBuf(), 0, aadData.size());
            aadFinished = true;
        }

        if ((inOff + len) > input.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        if ((outOff + len) > output.length)
        {
            throw new OutputLengthException("output buffer too short");
        }
        getKeyStream(input, inOff, len, output, outOff);
        return len;
    }

    public void reset()
    {
        reset(true);
    }

    private void reset(boolean clearMac)
    {
        if (clearMac)
        {
            this.mac = null;
        }
        this.aadData.reset();
        this.aadFinished = false;

        setKey(workingKey, workingIV);
        initGrain();
    }

    private byte[] getKeyStream(byte[] input, int inOff, int len, byte[] ciphertext, int outOff)
    {
        for (int i = 0; i < len; ++i)
        {
            byte cc = 0, input_i = input[inOff + i];
            for (int j = 0; j < 8; ++j)
            {
                int output = getOutput();
                nfsr = shift(nfsr, (getOutputNFSR() ^ lfsr[0]) & 1);
                lfsr = shift(lfsr, (getOutputLFSR()) & 1);

                int input_i_j = (input_i >> j) & 1;
                cc |= (input_i_j ^ output) << j;

//                if (input_i_j != 0)
//                {
//                    accumulate();
//                }
                int mask = -input_i_j;
                authAcc[0] ^= authSr[0] & mask;
                authAcc[1] ^= authSr[1] & mask;

                authShift(getOutput());
                nfsr = shift(nfsr, (getOutputNFSR() ^ lfsr[0]) & 1);
                lfsr = shift(lfsr, (getOutputLFSR()) & 1);
            }
            ciphertext[outOff + i] = cc;
        }

        return ciphertext;
    }

    public void processAADByte(byte in)
    {
        if (aadFinished)
        {
            throw new IllegalStateException("associated data must be added before plaintext/ciphertext");
        }
        aadData.write(in);
    }

    public void processAADBytes(byte[] input, int inOff, int len)
    {
        if (aadFinished)
        {
            throw new IllegalStateException("associated data must be added before plaintext/ciphertext");
        }
        aadData.write(input, inOff, len);
    }

    private void doProcessAADBytes(byte[] input, int inOff, int len)
    {
        byte[] ader;
        int aderlen;
        //encodeDer
        if (len < 128)
        {
            ader = new byte[1 + len];
            ader[0] = (byte)len;
            aderlen = 0;
        }
        else
        {
            // aderlen is the highest bit position divided by 8
            aderlen = len_length(len);
            ader = new byte[1 + aderlen + len];
            ader[0] = (byte)(0x80 | aderlen);
            int tmp = len;
            for (int i = 0; i < aderlen; ++i)
            {
                ader[1 + i] = (byte)tmp;
                tmp >>>= 8;
            }
        }
        for (int i = 0; i < len; ++i)
        {
            ader[1 + aderlen + i] = input[inOff + i];
        }

        for (int i = 0; i < ader.length; ++i)
        {
            byte ader_i = ader[i];
            for (int j = 0; j < 8; ++j)
            {
                nfsr = shift(nfsr, (getOutputNFSR() ^ lfsr[0]) & 1);
                lfsr = shift(lfsr, (getOutputLFSR()) & 1);

                int ader_i_j = (ader_i >> j) & 1;
//                if (ader_i_j != 0)
//                {
//                    accumulate();
//                }
                int mask = -ader_i_j;
                authAcc[0] ^= authSr[0] & mask;
                authAcc[1] ^= authSr[1] & mask;

                authShift(getOutput());
                nfsr = shift(nfsr, (getOutputNFSR() ^ lfsr[0]) & 1);
                lfsr = shift(lfsr, (getOutputLFSR()) & 1);
            }
        }
    }

    private void accumulate()
    {
        authAcc[0] ^= authSr[0];
        authAcc[1] ^= authSr[1];
    }

    private void authShift(int val)
    {
        authSr[0] = (authSr[0] >>> 1) | (authSr[1] << 31);
        authSr[1] = (authSr[1] >>> 1) | (val << 31);
    }

    public int processByte(byte input, byte[] output, int outOff)
        throws DataLengthException
    {
        return processBytes(new byte[]{input}, 0, 1, output, outOff);
    }

    public int doFinal(byte[] out, int outOff)
        throws IllegalStateException, InvalidCipherTextException
    {
        if (!aadFinished)
        {
            doProcessAADBytes(aadData.getBuf(), 0, aadData.size());
            aadFinished = true;
        }

        accumulate();

        this.mac = Pack.intToLittleEndian(authAcc);

        System.arraycopy(mac, 0, out, outOff, mac.length);

        reset(false);

        return mac.length;
    }

    public byte[] getMac()
    {
        return mac;
    }

    public int getUpdateOutputSize(int len)
    {
        return len;
    }

    public int getOutputSize(int len)
    {
        //the last 8 bytes are from AD
        return len + 8;
    }

    private static int len_length(int v)
    {
        if ((v & 0xff) == v)
        {
            return 1;
        }
        if ((v & 0xffff) == v)
        {
            return 2;
        }
        if ((v & 0xffffff) == v)
        {
            return 3;
        }

        return 4;
    }

    private static final class ErasableOutputStream
        extends ByteArrayOutputStream
    {
        public ErasableOutputStream()
        {
        }

        public byte[] getBuf()
        {
            return buf;
        }

//        public void erase()
//        {
//            Arrays.fill(this.buf, (byte)0);
//            // this for JVM compatibility
//            this.reset();
//        }
    }
}
