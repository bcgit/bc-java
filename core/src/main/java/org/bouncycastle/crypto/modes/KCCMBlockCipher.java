package org.bouncycastle.crypto.modes;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/**
 * Implementation of DSTU7624 CCM mode
 */
public class KCCMBlockCipher
    implements AEADBlockCipher
{

    private static final int BYTES_IN_INT = 4;
    private static final int BITS_IN_BYTE = 8;

    private static final int MAX_MAC_BIT_LENGTH = 512;
    private static final int MIN_MAC_BIT_LENGTH = 64;

    private BlockCipher engine;

    private int macSize;
    private boolean forEncryption;

    private byte[] initialAssociatedText;
    private byte[] mac;
    private byte[] macBlock;

    private byte[] nonce;

    private byte[] G1;
    private byte[] buffer;

    private byte[] s;
    private byte[] counter;


    private ExposedByteArrayOutputStream associatedText = new ExposedByteArrayOutputStream();
    private ExposedByteArrayOutputStream data = new ExposedByteArrayOutputStream();


    private int Nb_ = 4;

    private void setNb(int Nb)
    {
        if (Nb == 4 || Nb == 6 || Nb == 8)
        {
            Nb_ = Nb;
        }
        else
        {
            throw new IllegalArgumentException("Nb = 4 is recommended by DSTU7624 but can be changed to only 6 or 8 in this implementation");
        }
    }

    /**
     * Base constructor. Nb value is set to 4.
     *
     * @param engine base cipher to use under CCM.
     */
    public KCCMBlockCipher(BlockCipher engine)
    {
        this(engine, 4);
    }

    /**
     * Constructor allowing Nb configuration.
     * <p>
     * Nb is a parameter specified in CCM mode of DSTU7624 standard.
     * This parameter specifies maximum possible length of input. It should
     * be calculated as follows: Nb = 1/8 * (-3 + log[2]Nmax) + 1,
     * where Nmax - length of input message in bits. For practical reasons
     * Nmax usually less than 4Gb, e.g. for Nmax = 2^32 - 1, Nb = 4.
     * </p>
     * @param engine base cipher to use under CCM.
     * @param nB Nb value to use.
     */
    public KCCMBlockCipher(BlockCipher engine, int nB)
    {
        this.engine = engine;
        this.macSize = engine.getBlockSize();
        this.nonce = new byte[engine.getBlockSize()];
        this.initialAssociatedText = new byte[engine.getBlockSize()];
        this.mac = new byte[engine.getBlockSize()];
        this.macBlock = new byte[engine.getBlockSize()];
        this.G1 = new byte[engine.getBlockSize()];
        this.buffer = new byte[engine.getBlockSize()];
        this.s = new byte[engine.getBlockSize()];
        this.counter = new byte[engine.getBlockSize()];
        setNb(nB);
    }

    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {

        CipherParameters cipherParameters;
        if (params instanceof AEADParameters)
        {

            AEADParameters parameters = (AEADParameters)params;

            if (parameters.getMacSize() > MAX_MAC_BIT_LENGTH || parameters.getMacSize() < MIN_MAC_BIT_LENGTH || parameters.getMacSize() % 8 != 0)
            {
                throw new IllegalArgumentException("Invalid mac size specified");
            }

            nonce = parameters.getNonce();
            macSize = parameters.getMacSize() / BITS_IN_BYTE;
            initialAssociatedText = parameters.getAssociatedText();
            cipherParameters = parameters.getKey();
        }
        else if (params instanceof ParametersWithIV)
        {
            nonce = ((ParametersWithIV)params).getIV();
            macSize = engine.getBlockSize(); // use default blockSize for MAC if it is not specified
            initialAssociatedText = null;
            cipherParameters = ((ParametersWithIV)params).getParameters();
        }
        else
        {
            throw new IllegalArgumentException("Invalid parameters specified");
        }

        this.mac = new byte[macSize];
        this.forEncryption = forEncryption;
        engine.init(true, cipherParameters);

        counter[0] = 0x01; // defined in standard

        if (initialAssociatedText != null)
        {
            processAADBytes(initialAssociatedText, 0, initialAssociatedText.length);
        }
    }

    public String getAlgorithmName()
    {
        return engine.getAlgorithmName() + "/KCCM";
    }

    public BlockCipher getUnderlyingCipher()
    {
        return engine;
    }

    public void processAADByte(byte in)
    {
        associatedText.write(in);
    }

    public void processAADBytes(byte[] in, int inOff, int len)
    {
        associatedText.write(in, inOff, len);
    }

    private void processAAD(byte[] assocText, int assocOff, int assocLen, int dataLen)
    {
        if (assocLen - assocOff < engine.getBlockSize())
        {
            throw new IllegalArgumentException("authText buffer too short");
        }
        if (assocLen % engine.getBlockSize() != 0)
        {
            throw new IllegalArgumentException("padding not supported");
        }

        System.arraycopy(nonce, 0, G1, 0, nonce.length - Nb_ - 1);

        intToBytes(dataLen, buffer, 0); // for G1

        System.arraycopy(buffer, 0, G1, nonce.length - Nb_ - 1, BYTES_IN_INT);

        G1[G1.length - 1] = getFlag(true, macSize);

        engine.processBlock(G1, 0, macBlock, 0);

        intToBytes(assocLen, buffer, 0); // for G2

        if (assocLen <= engine.getBlockSize() - Nb_)
        {
            for (int byteIndex = 0; byteIndex < assocLen; byteIndex++)
            {
                buffer[byteIndex + Nb_] ^= assocText[assocOff + byteIndex];
            }

            for (int byteIndex = 0; byteIndex < engine.getBlockSize(); byteIndex++)
            {
                macBlock[byteIndex] ^= buffer[byteIndex];
            }

            engine.processBlock(macBlock, 0, macBlock, 0);

            return;
        }

        for (int byteIndex = 0; byteIndex < engine.getBlockSize(); byteIndex++)
        {
            macBlock[byteIndex] ^= buffer[byteIndex];
        }

        engine.processBlock(macBlock, 0, macBlock, 0);

        int authLen = assocLen;
        while (authLen != 0)
        {
            for (int byteIndex = 0; byteIndex < engine.getBlockSize(); byteIndex++)
            {
                macBlock[byteIndex] ^= assocText[byteIndex + assocOff];
            }

            engine.processBlock(macBlock, 0, macBlock, 0);

            assocOff += engine.getBlockSize();
            authLen -= engine.getBlockSize();
        }
    }

    public int processByte(byte in, byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        data.write(in);

        return 0;
    }

    public int processBytes(byte[] in, int inOff, int inLen, byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        if (in.length < (inOff + inLen))
        {
            throw new DataLengthException("input buffer too short");
        }
        data.write(in, inOff, inLen);

        return 0;
    }

    public int processPacket(byte[] in, int inOff, int len, byte[] out, int outOff)
        throws IllegalStateException, InvalidCipherTextException
    {
        if (in.length - inOff < len)
        {
            throw new DataLengthException("input buffer too short");
        }
        if (out.length - outOff < len)
        {
            throw new OutputLengthException("output buffer too short");
        }

        if (associatedText.size() > 0)
        {
            if (forEncryption)
            {
                processAAD(associatedText.getBuffer(), 0, associatedText.size(), data.size());
            }
            else
            {
                processAAD(associatedText.getBuffer(), 0, associatedText.size(), data.size() - macSize);
            }
        }

        if (forEncryption)
        {
            if ((len % engine.getBlockSize()) != 0)
            {
                throw new DataLengthException("partial blocks not supported");
            }

            CalculateMac(in, inOff, len);
            engine.processBlock(nonce, 0, s, 0);

            int totalLength = len;
            while (totalLength > 0)
            {
                ProcessBlock(in, inOff, len, out, outOff);
                totalLength -= engine.getBlockSize();
                inOff += engine.getBlockSize();
                outOff += engine.getBlockSize();
            }

            for (int byteIndex = 0; byteIndex < counter.length; byteIndex++)
            {
                s[byteIndex] += counter[byteIndex];
            }

            engine.processBlock(s, 0, buffer, 0);

            for (int byteIndex = 0; byteIndex < macSize; byteIndex++)
            {
                out[outOff + byteIndex] = (byte)(buffer[byteIndex] ^ macBlock[byteIndex]);
            }

            System.arraycopy(macBlock, 0, mac, 0, macSize);
            
            reset();

            return len + macSize;
        }
        else
        {
            if ((len - macSize) % engine.getBlockSize() != 0)
            {
                throw new DataLengthException("partial blocks not supported");
            }

            engine.processBlock(nonce, 0, s, 0);

            int blocks = len / engine.getBlockSize();

            for (int blockNum = 0; blockNum < blocks; blockNum++)
            {
                ProcessBlock(in, inOff, len, out, outOff);

                inOff += engine.getBlockSize();
                outOff += engine.getBlockSize();
            }

            if (len > inOff)
            {
                for (int byteIndex = 0; byteIndex < counter.length; byteIndex++)
                {
                    s[byteIndex] += counter[byteIndex];
                }

                engine.processBlock(s, 0, buffer, 0);

                for (int byteIndex = 0; byteIndex < macSize; byteIndex++)
                {
                    out[outOff + byteIndex] = (byte)(buffer[byteIndex] ^ in[inOff + byteIndex]);
                }
                outOff += macSize;
            }

            for (int byteIndex = 0; byteIndex < counter.length; byteIndex++)
            {
                s[byteIndex] += counter[byteIndex];
            }

            engine.processBlock(s, 0, buffer, 0);

            System.arraycopy(out, outOff - macSize, buffer, 0, macSize);

            CalculateMac(out, 0, outOff - macSize);

            System.arraycopy(macBlock, 0, mac, 0, macSize);

            byte[] calculatedMac = new byte[macSize];

            System.arraycopy(buffer, 0, calculatedMac, 0, macSize);

            if (!Arrays.constantTimeAreEqual(mac, calculatedMac))
            {
                throw new InvalidCipherTextException("mac check failed");
            }

            reset();

            return len - macSize;
        }
    }

    private void ProcessBlock(byte[] input, int inOff, int len, byte[] output, int outOff)
    {

        for (int byteIndex = 0; byteIndex < counter.length; byteIndex++)
        {
            s[byteIndex] += counter[byteIndex];
        }

        engine.processBlock(s, 0, buffer, 0);

        for (int byteIndex = 0; byteIndex < engine.getBlockSize(); byteIndex++)
        {
            output[outOff + byteIndex] = (byte)(buffer[byteIndex] ^ input[inOff + byteIndex]);
        }
    }

    private void CalculateMac(byte[] authText, int authOff, int len)
    {
        int totalLen = len;
        while (totalLen > 0)
        {
            for (int byteIndex = 0; byteIndex < engine.getBlockSize(); byteIndex++)
            {
                macBlock[byteIndex] ^= authText[authOff + byteIndex];
            }

            engine.processBlock(macBlock, 0, macBlock, 0);

            totalLen -= engine.getBlockSize();
            authOff += engine.getBlockSize();
        }
    }

    public int doFinal(byte[] out, int outOff)
        throws IllegalStateException, InvalidCipherTextException
    {
        int len = processPacket(data.getBuffer(), 0, data.size(), out, outOff);

        reset();

        return len;
    }

    public byte[] getMac()
    {
        return Arrays.clone(mac);
    }

    public int getUpdateOutputSize(int len)
    {
        return len;
    }

    public int getOutputSize(int len)
    {
        return len + macSize;
    }

    public void reset()
    {
        Arrays.fill(G1, (byte)0);
        Arrays.fill(buffer, (byte)0);
        Arrays.fill(counter, (byte)0);
        Arrays.fill(macBlock, (byte)0);
        counter[0] = 0x01;
        data.reset();
        associatedText.reset();

        if (initialAssociatedText != null)
        {
            processAADBytes(initialAssociatedText, 0, initialAssociatedText.length);
        }
    }


    private void intToBytes(
        int num,
        byte[] outBytes,
        int outOff)
    {
        outBytes[outOff + 3] = (byte)(num >> 24);
        outBytes[outOff + 2] = (byte)(num >> 16);
        outBytes[outOff + 1] = (byte)(num >> 8);
        outBytes[outOff] = (byte)num;
    }

    private byte getFlag(boolean authTextPresents, int macSize)
    {
        StringBuffer flagByte = new StringBuffer();

        if (authTextPresents)
        {
            flagByte.append("1");
        }
        else
        {
            flagByte.append("0");
        }


        switch (macSize)
        {
        case 8:
            flagByte.append("010"); // binary 2
            break;
        case 16:
            flagByte.append("011"); // binary 3
            break;
        case 32:
            flagByte.append("100"); // binary 4
            break;
        case 48:
            flagByte.append("101"); // binary 5
            break;
        case 64:
            flagByte.append("110"); // binary 6
            break;
        }

        String binaryNb = Integer.toBinaryString(Nb_ - 1);
        while (binaryNb.length() < 4)
        {
            binaryNb = new StringBuffer(binaryNb).insert(0, "0").toString();
        }

        flagByte.append(binaryNb);

        return (byte)Integer.parseInt(flagByte.toString(), 2);

    }

    private class ExposedByteArrayOutputStream
        extends ByteArrayOutputStream
    {
        public ExposedByteArrayOutputStream()
        {
        }

        public byte[] getBuffer()
        {
            return this.buf;
        }
    }

}
