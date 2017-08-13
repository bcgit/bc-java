package org.bouncycastle.crypto.engines;

import java.util.ArrayList;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.util.Arrays;

/**
 * Implementation of DSTU7624 KEY WRAP mode
 */
public class DSTU7624WrapEngine
    implements Wrapper
{

    private static final int BYTES_IN_INTEGER = 4;

    private boolean forWrapping;
    private DSTU7624Engine engine;

    private byte[] B, intArray;
    private byte[] checkSumArray, zeroArray;
    private ArrayList<byte[]> Btemp;


    public DSTU7624WrapEngine(int blockBitLength)
    {

        this.engine = new DSTU7624Engine(blockBitLength);
        this.B = new byte[engine.getBlockSize() / 2];
        this.checkSumArray = new byte[engine.getBlockSize()];
        this.zeroArray = new byte[engine.getBlockSize()];
        this.Btemp = new ArrayList<byte[]>();
        this.intArray = new byte[BYTES_IN_INTEGER];

    }

    public void init(boolean forWrapping, CipherParameters param)
    {
        if (param instanceof ParametersWithRandom)
        {
            param = ((ParametersWithRandom)param).getParameters();
        }

        this.forWrapping = forWrapping;
        if (param instanceof KeyParameter)
        {
            engine.init(forWrapping, param);
        }
        else
        {
            throw new IllegalArgumentException("invalid parameters passed to DSTU7624WrapEngine");
        }

    }

    public String getAlgorithmName()
    {
        return "DSTU7624WrapEngine";
    }

    public byte[] wrap(byte[] in, int inOff, int inLen)
    {
        if (!forWrapping)
        {
            throw new IllegalStateException("not set for wrapping");
        }

        if ((inLen % engine.getBlockSize()) != 0)
        {
            //Partial blocks not supported
            throw new DataLengthException("wrap data must be a multiple of " + engine.getBlockSize() + " bytes");
        }

        if (inOff + inLen > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        int n = 2 * (1 + inLen / engine.getBlockSize()); /* Defined in DSTU7624 standard */
        int V = (n - 1) * 6; /* Defined in DSTU7624 standard */


        byte[] wrappedBuffer = new byte[inLen + engine.getBlockSize()];
        System.arraycopy(in, inOff, wrappedBuffer, 0, inLen);

        System.arraycopy(wrappedBuffer, 0, B, 0, engine.getBlockSize() / 2);

        Btemp.clear();

        int bHalfBlocksLen = wrappedBuffer.length - engine.getBlockSize() / 2;
        int bufOff = engine.getBlockSize() / 2;
        while (bHalfBlocksLen != 0)
        {
            byte[] temp = new byte[engine.getBlockSize() / 2];
            System.arraycopy(wrappedBuffer, bufOff, temp, 0, engine.getBlockSize() / 2);

            Btemp.add(temp);

            bHalfBlocksLen -= engine.getBlockSize() / 2;
            bufOff += engine.getBlockSize() / 2;
        }

        for (int j = 0; j < V; j++)
        {
            System.arraycopy(B, 0, wrappedBuffer, 0, engine.getBlockSize() / 2);
            System.arraycopy(Btemp.get(0), 0, wrappedBuffer, engine.getBlockSize() / 2, engine.getBlockSize() / 2);

            engine.processBlock(wrappedBuffer, 0, wrappedBuffer, 0);

            intToBytes(j + 1, intArray, 0);
            for (int byteNum = 0; byteNum < BYTES_IN_INTEGER; byteNum++)
            {
                wrappedBuffer[byteNum + engine.getBlockSize() / 2] ^= intArray[byteNum];
            }

            System.arraycopy(wrappedBuffer, engine.getBlockSize() / 2, B, 0, engine.getBlockSize() / 2);

            for (int i = 2; i < n; i++)
            {
                System.arraycopy(Btemp.get(i - 1), 0, Btemp.get(i - 2), 0, engine.getBlockSize() / 2);
            }

            System.arraycopy(wrappedBuffer, 0, Btemp.get(n - 2), 0, engine.getBlockSize() / 2);
        }


        System.arraycopy(B, 0, wrappedBuffer, 0, engine.getBlockSize() / 2);
        bufOff = engine.getBlockSize() / 2;

        for (int i = 0; i < n - 1; i++)
        {
            System.arraycopy(Btemp.get(i), 0, wrappedBuffer, bufOff, engine.getBlockSize() / 2);
            bufOff += engine.getBlockSize() / 2;
        }

        return wrappedBuffer;

    }

    public byte[] unwrap(byte[] in, int inOff, int inLen)
        throws InvalidCipherTextException
    {
        if (forWrapping)
        {
            throw new IllegalStateException("not set for unwrapping");
        }

        if ((inLen % engine.getBlockSize()) != 0)
        {
            //Partial blocks not supported
            throw new DataLengthException("unwrap data must be a multiple of " + engine.getBlockSize() + " bytes");
        }

        int n = 2 * inLen / engine.getBlockSize();

        int V = (n - 1) * 6;

        byte[] buffer = new byte[inLen];
        System.arraycopy(in, inOff, buffer, 0, inLen);

        byte[] B = new byte[engine.getBlockSize() / 2];
        System.arraycopy(buffer, 0, B, 0, engine.getBlockSize() / 2);

        Btemp.clear();

        int bHalfBlocksLen = buffer.length - engine.getBlockSize() / 2;
        int bufOff = engine.getBlockSize() / 2;
        while (bHalfBlocksLen != 0)
        {
            byte[] temp = new byte[engine.getBlockSize() / 2];
            System.arraycopy(buffer, bufOff, temp, 0, engine.getBlockSize() / 2);

            Btemp.add(temp);

            bHalfBlocksLen -= engine.getBlockSize() / 2;
            bufOff += engine.getBlockSize() / 2;
        }

        for (int j = 0; j < V; j++)
        {
            System.arraycopy(Btemp.get(n - 2), 0, buffer, 0, engine.getBlockSize() / 2);
            System.arraycopy(B, 0, buffer, engine.getBlockSize() / 2, engine.getBlockSize() / 2);
            intToBytes(V - j, intArray, 0);
            for (int byteNum = 0; byteNum < BYTES_IN_INTEGER; byteNum++)
            {
                buffer[byteNum + engine.getBlockSize() / 2] ^= intArray[byteNum];
            }

            engine.processBlock(buffer, 0, buffer, 0);

            System.arraycopy(buffer, 0, B, 0, engine.getBlockSize() / 2);

            for (int i = 2; i < n; i++)
            {
                System.arraycopy(Btemp.get(n - i - 1), 0, Btemp.get(n - i), 0, engine.getBlockSize() / 2);
            }

            System.arraycopy(buffer, engine.getBlockSize() / 2, Btemp.get(0), 0, engine.getBlockSize() / 2);
        }

        System.arraycopy(B, 0, buffer, 0, engine.getBlockSize() / 2);
        bufOff = engine.getBlockSize() / 2;

        for (int i = 0; i < n - 1; i++)
        {
            System.arraycopy(Btemp.get(i), 0, buffer, bufOff, engine.getBlockSize() / 2);
            bufOff += engine.getBlockSize() / 2;
        }

        System.arraycopy(buffer, buffer.length - engine.getBlockSize(), checkSumArray, 0, engine.getBlockSize());

        byte[] wrappedBuffer = new byte[buffer.length - engine.getBlockSize()];
        if (!Arrays.areEqual(checkSumArray, zeroArray))
        {
            throw new InvalidCipherTextException("checksum failed");
        }
        else
        {
            System.arraycopy(buffer, 0, wrappedBuffer, 0, buffer.length - engine.getBlockSize());
        }


        return wrappedBuffer;
    }


    private void intToBytes(int number, byte[] outBytes, int outOff)
    {
        outBytes[outOff + 3] = (byte)(number >> 24);
        outBytes[outOff + 2] = (byte)(number >> 16);
        outBytes[outOff + 1] = (byte)(number >> 8);
        outBytes[outOff] = (byte)number;
    }
}
