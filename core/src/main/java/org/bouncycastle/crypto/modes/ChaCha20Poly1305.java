package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class ChaCha20Poly1305
    implements AEADCipher
{
    private static final class State
    {
        public static final int UNINITIALIZED = 0;
        public static final int ENC_AAD = 1;
        public static final int ENC_DATA = 2;
        public static final int DEC_AAD = 3;
        public static final int DEC_DATA = 4;
    }

    private static final int MAC_SIZE = 16;
    private static final int BUF_SIZE = MAC_SIZE * 4;
    private static final byte[] ZEROES = new byte[MAC_SIZE - 1];

    // TODO RFC 7593 allows up to 2^64 - 1
    private static final long AAD_LIMIT = Long.MAX_VALUE;
    private static final long DATA_LIMIT = ((1L << 32) - 1) * 64;

    private final StreamCipher chacha20;
    private final Mac poly1305;

    private final byte[] buf = new byte[BUF_SIZE + MAC_SIZE];
    private final byte[] mac = new byte[MAC_SIZE];

    private byte[] initialAAD;

    private long aadCount;
    private long dataCount;
    private int state = State.UNINITIALIZED;
    private int bufPos;

    public ChaCha20Poly1305()
    {
        this(new ChaCha7539Engine(), new Poly1305());
    }

    public ChaCha20Poly1305(StreamCipher chacha20, Mac poly1305)
    {
        if (null == chacha20)
        {
            throw new NullPointerException("'chacha20' cannot be null");
        }
        if (null == poly1305)
        {
            throw new NullPointerException("'poly1305' cannot be null");
        }
        if (MAC_SIZE != poly1305.getMacSize())
        {
            throw new IllegalArgumentException("'poly1305' must be a 128-bit MAC");
        }

        this.chacha20 = chacha20;
        this.poly1305 = poly1305;
    }

    public String getAlgorithmName()
    {
        return "ChaCha20Poly1305";
    }

    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException
    {
        this.state = forEncryption ? State.ENC_AAD : State.DEC_AAD;

        CipherParameters chacha20Params;
        if (params instanceof AEADParameters)
        {
            AEADParameters param = (AEADParameters)params;

            int macSizeBits = param.getMacSize();
            if ((MAC_SIZE * 8) != macSizeBits)
            {
                throw new IllegalArgumentException("Invalid value for MAC size: " + macSizeBits);
            }

            chacha20Params = new ParametersWithIV(param.getKey(), param.getNonce());

            this.initialAAD = param.getAssociatedText();
        }
        else
        {
            throw new IllegalArgumentException("invalid parameters passed to ChaCha20Poly1305");
        }

        chacha20.init(forEncryption, chacha20Params);

        reset(true, false);
    }

    public int getOutputSize(int len)
    {
        int total = Math.max(0, len) + bufPos;

        switch (state)
        {
        case State.DEC_AAD:
        case State.DEC_DATA:
            return Math.max(0, total - MAC_SIZE);
        case State.ENC_AAD:
        case State.ENC_DATA:
            return total + MAC_SIZE;
        default:
            throw new IllegalStateException();
        }
    }

    public int getUpdateOutputSize(int len)
    {
        int total = Math.max(0, len) + bufPos;

        switch (state)
        {
        case State.DEC_AAD:
        case State.DEC_DATA:
            total = Math.max(0, total - MAC_SIZE);
            break;
        case State.ENC_AAD:
        case State.ENC_DATA:
            break;
        default:
            throw new IllegalStateException();
        }

        return total - (total % BUF_SIZE);
    }

    public void processAADByte(byte in)
    {
        switch (state)
        {
        case State.DEC_AAD:
        case State.ENC_AAD:
        {
            this.aadCount = incrementCount(aadCount, 1, AAD_LIMIT);
            poly1305.update(in);
            break;
        }
        default:
            throw new IllegalStateException();
        }
    }

    public void processAADBytes(byte[] in, int inOff, int len)
    {
        if (null == in)
        {
            throw new NullPointerException("'in' cannot be null");
        }
        if (inOff < 0)
        {
            throw new IllegalArgumentException("'inOff' cannot be negative");
        }
        if (len < 0)
        {
            throw new IllegalArgumentException("'len' cannot be negative");
        }
        if (inOff > (in.length - len))
        {
            throw new DataLengthException("Input buffer too short");
        }

        switch (state)
        {
        case State.DEC_AAD:
        case State.ENC_AAD:
        {
            if (len > 0)
            {
                this.aadCount = incrementCount(aadCount, len, AAD_LIMIT);
                poly1305.update(in, inOff, len);
            }
            break;
        }
        default:
            throw new IllegalStateException();
        }
    }

    public int processByte(byte in, byte[] out, int outOff) throws DataLengthException
    {
        checkAAD();

        switch (state)
        {
        case State.DEC_DATA:
        {
            buf[bufPos] = in;
            if (++bufPos == buf.length)
            {
                poly1305.update(buf, 0, BUF_SIZE);
                processData(buf, 0, BUF_SIZE, out, outOff);
                System.arraycopy(buf, BUF_SIZE, buf, 0, MAC_SIZE);
                this.bufPos = MAC_SIZE;
                return BUF_SIZE;
            }

            return 0;
        }
        case State.ENC_DATA:
        {
            buf[bufPos] = in;
            if (++bufPos == BUF_SIZE)
            {
                processData(buf, 0, BUF_SIZE, out, outOff);
                poly1305.update(out, outOff, BUF_SIZE);
                this.bufPos = 0;
                return BUF_SIZE;
            }

            return 0;
        }
        default:
            throw new IllegalStateException();
        }
    }

    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff) throws DataLengthException
    {
        if (null == in)
        {
            throw new NullPointerException("'in' cannot be null");
        }
        if (null == out)
        {
            throw new NullPointerException("'out' cannot be null");
        }
        if (inOff < 0)
        {
            throw new IllegalArgumentException("'inOff' cannot be negative");
        }
        if (len < 0)
        {
            throw new IllegalArgumentException("'len' cannot be negative");
        }
        if (inOff > (in.length - len))
        {
            throw new DataLengthException("Input buffer too short");
        }
        if (outOff < 0)
        {
            throw new IllegalArgumentException("'outOff' cannot be negative");
        }

        checkAAD();

        int resultLen = 0;

        switch (state)
        {
        case State.DEC_DATA:
        {
            for (int i = 0; i < len; ++i)
            {
                buf[bufPos] = in[inOff + i];
                if (++bufPos == buf.length)
                {
                    poly1305.update(buf, 0, BUF_SIZE);
                    processData(buf, 0, BUF_SIZE, out, outOff + resultLen);
                    System.arraycopy(buf, BUF_SIZE, buf, 0, MAC_SIZE);
                    this.bufPos = MAC_SIZE;
                    resultLen += BUF_SIZE;
                }
            }
            break;
        }
        case State.ENC_DATA:
        {
            for (int i = 0; i < len; ++i)
            {
                buf[bufPos] = in[inOff + i];
                if (++bufPos == BUF_SIZE)
                {
                    processData(buf, 0, BUF_SIZE, out, outOff + resultLen);
                    poly1305.update(out, outOff + resultLen, BUF_SIZE);
                    this.bufPos = 0;
                    resultLen += BUF_SIZE;
                }
            }
            break;
        }
        default:
            throw new IllegalStateException();
        }

        return resultLen;
    }

    public int doFinal(byte[] out, int outOff) throws IllegalStateException, InvalidCipherTextException
    {
        if (null == out)
        {
            throw new NullPointerException("'out' cannot be null");
        }
        if (outOff < 0)
        {
            throw new IllegalArgumentException("'outOff' cannot be negative");
        }

        Arrays.clear(mac);

        checkAAD();

        int resultLen = 0;

        switch (state)
        {
        case State.DEC_DATA:
        {
            if (bufPos < MAC_SIZE)
            {
                throw new InvalidCipherTextException("data too short");
            }

            resultLen = bufPos - MAC_SIZE;

            if (outOff > (out.length - resultLen))
            {
                throw new OutputLengthException("Output buffer too short");
            }

            if (resultLen > 0)
            {
                poly1305.update(buf, 0, resultLen);
                processData(buf, 0, resultLen, out, outOff);
            }

            finishData();

            if (!Arrays.constantTimeAreEqual(MAC_SIZE, mac, 0, buf, resultLen))
            {
                throw new InvalidCipherTextException("mac check in ChaCha20Poly1305 failed");
            }

            break;
        }
        case State.ENC_DATA:
        {
            resultLen = bufPos + MAC_SIZE;

            if (outOff > (out.length - resultLen))
            {
                throw new OutputLengthException("Output buffer too short");
            }

            if (bufPos > 0)
            {
                processData(buf, 0, bufPos, out, outOff);
                poly1305.update(out, outOff, bufPos);
            }

            finishData();

            System.arraycopy(mac, 0, out, outOff + bufPos, MAC_SIZE);
            break;
        }
        default:
            throw new IllegalStateException();
        }

        reset(false, true);

        return resultLen;
    }

    public byte[] getMac()
    {
        return Arrays.clone(mac);
    }

    public void reset()
    {
        reset(true, true);
    }

    private void checkAAD()
    {
        switch (state)
        {
        case State.DEC_AAD:
        {
            finishAAD();
            this.state = State.DEC_DATA;
            break;
        }
        case State.ENC_AAD:
        {
            finishAAD();
            this.state = State.ENC_DATA;
            break;
        }
        }
    }

    private void finishAAD()
    {
        padMAC(aadCount);
    }

    private void finishData()
    {
        padMAC(dataCount);

        byte[] lengths = new byte[16];
        Pack.longToLittleEndian(aadCount, lengths, 0);
        Pack.longToLittleEndian(dataCount, lengths, 8);
        poly1305.update(lengths, 0, 16);

        poly1305.doFinal(mac, 0);
    }

    private long incrementCount(long count, long increment, long limit)
    {
        if (count > (limit - increment))
        {
            throw new IllegalStateException("Limit exceeded");
        }

        return count + increment;
    }

    private void initMAC()
    {
        byte[] firstBlock = new byte[64];
        try
        {
            chacha20.processBytes(firstBlock, 0, 64, firstBlock, 0);
            poly1305.init(new KeyParameter(firstBlock, 0, 32));
        }
        finally
        {
            Arrays.clear(firstBlock);
        }
    }

    private void padMAC(long count)
    {
        int partial = (int)count % MAC_SIZE;
        if (0 != partial)
        {
            poly1305.update(ZEROES, 0, MAC_SIZE - partial);
        }
    }

    private void processData(byte[] in, int inOff, int inLen, byte[] out, int outOff)
    {
        if (outOff > (out.length - inLen))
        {
            throw new OutputLengthException("Output buffer too short");
        }

        chacha20.processBytes(in, inOff, inLen, out, outOff);

        this.dataCount = incrementCount(dataCount, inLen, DATA_LIMIT);
    }

    private void reset(boolean clearMac, boolean resetCipher)
    {
        switch (state)
        {
        case State.DEC_AAD:
        case State.ENC_AAD:
            break;
        case State.DEC_DATA:
            this.state = State.DEC_AAD;
            break;
        case State.ENC_DATA:
            this.state = State.ENC_AAD;
            break;
        default:
            throw new IllegalStateException();
        }

        Arrays.clear(buf);

        if (clearMac)
        {
            Arrays.clear(mac);
        }

        this.aadCount = 0L;
        this.dataCount = 0L;
        this.bufPos = 0;

        if (resetCipher)
        {
            chacha20.reset();
        }

        initMAC();

        if (null != initialAAD)
        {
            this.aadCount = incrementCount(aadCount, initialAAD.length, AAD_LIMIT);
            poly1305.update(initialAAD, 0, initialAAD.length);
        }
    }
}
