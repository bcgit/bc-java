package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class Blake2bpDigest
    implements ExtendedDigest
{

    private int bufferPos = 0; // a value from 0 up to BLOCK_LENGTH_BYTES

    private int keyLength = 0; // 0 - 64 bytes
    private int digestLength; // 0 - 64 bytes
    private int fanout; // 0-255
    private int depth; // 0-255

    private int nodeOffset = 0;
    private long innerHashLength;

    private Blake2bDigest[] S = new Blake2bDigest[4];
    private Blake2bDigest root;

    private byte[] buffer = null;

    private byte[] salt = null;
    private byte[] param = null;
    private byte[] key = null;
    private final int BLAKE2B_BLOCKBYTES = 128;
    private final int BLAKE2B_KEYBYTES = 64;
    private final int BLAKE2B_OUTBYTES = 64;
    private final int PARALLELISM_DEGREE = 4;

    private final byte[] singleByte = new byte[1];

    public Blake2bpDigest(byte[] key)
    {
        param = new byte[64];
        buffer = new byte[512];
        init(key);
    }

    @Override
    public String getAlgorithmName()
    {
        return "BLAKE2bp";
    }

    @Override
    public int getDigestSize()
    {
        return digestLength;
    }

    @Override
    public void update(byte in)
    {
        singleByte[0] = in;
        update(singleByte, 0, 1);
    }

    @Override
    public void update(byte[] message, int offset, int len)
    {
        int left = bufferPos;
        int remainingLength = 8*BLAKE2B_BLOCKBYTES - left;

        if(left != 0 && len >= remainingLength)
        {
            System.arraycopy(message, offset, buffer, left, remainingLength);

            for (int i = 0; i < PARALLELISM_DEGREE; i++)
            {
                S[i].update(buffer, i * BLAKE2B_BLOCKBYTES, BLAKE2B_BLOCKBYTES);
            }
            offset += remainingLength;
            len -= remainingLength;
            left = 0;
        }

        //TODO: make threads run each iteration
        for (int i = 0; i < PARALLELISM_DEGREE; i++)
        {
            int inlen = len;
            int inOffset = offset;
            inOffset += i * BLAKE2B_BLOCKBYTES;

            while (inlen >= PARALLELISM_DEGREE * BLAKE2B_BLOCKBYTES)
            {
                S[i].update(message, inOffset, BLAKE2B_BLOCKBYTES);
                inOffset += PARALLELISM_DEGREE * BLAKE2B_BLOCKBYTES;
                inlen -= PARALLELISM_DEGREE * BLAKE2B_BLOCKBYTES;
            }
        }

        offset += len - len % ( PARALLELISM_DEGREE * BLAKE2B_BLOCKBYTES );
        len %= PARALLELISM_DEGREE * BLAKE2B_BLOCKBYTES;

        if(len > 0)
        {
            System.arraycopy(message, offset, buffer, left, len);
        }

        bufferPos = left + len;
    }

    @Override
    public int doFinal(byte[] out, int outOff)
    {
        byte[][] hash = new byte[PARALLELISM_DEGREE][BLAKE2B_OUTBYTES];

        int remainingLength = 0; // left bytes of buffer

        for (int i = 0; i < PARALLELISM_DEGREE; i++)
        {
            if (bufferPos > i * BLAKE2B_BLOCKBYTES)
            {
                remainingLength = bufferPos - i * BLAKE2B_BLOCKBYTES;
//                System.out.println("left: " + remainingLength);

                if (remainingLength > BLAKE2B_BLOCKBYTES)
                {
                    remainingLength = BLAKE2B_BLOCKBYTES;
                }

                S[i].update(buffer, i * BLAKE2B_BLOCKBYTES, remainingLength);
            }

            S[i].doFinal(hash[i], 0);
        }
        for (int i = 0; i < PARALLELISM_DEGREE; i++)
        {
            root.update(hash[i], 0, BLAKE2B_OUTBYTES);
        }
        int length = root.doFinal(out, outOff);

        reset();

        return length;
    }

    @Override
    public void reset()
    {
        bufferPos = 0;
        digestLength = 64;
        // init root
        root.reset();
        for (int i = 0; i < PARALLELISM_DEGREE; i++)
        {
            S[i].reset();
        }

        root.setAsLastNode();
        S[PARALLELISM_DEGREE-1].setAsLastNode();

        if(key != null)
        {
            byte[] block = new byte[BLAKE2B_BLOCKBYTES];
            System.arraycopy(key, 0, block, 0, keyLength);
            for (int i = 0; i < PARALLELISM_DEGREE; i++)
            {
                S[i].update(block, 0, BLAKE2B_BLOCKBYTES);
            }
        }
    }

    @Override
    public int getByteLength()
    {
        return 0;
    }

    private void init(byte[] key)
    {
        if (key != null && key.length > 0)
        {
            keyLength = key.length;
            if (keyLength > BLAKE2B_KEYBYTES)
            {
                throw new IllegalArgumentException("Keys > 64 bytes are not supported");
            }
            this.key = Arrays.clone(key);
        }

        bufferPos = 0;
        digestLength = 64;

        // init root
        fanout = PARALLELISM_DEGREE;
        depth = 2;
        innerHashLength = BLAKE2B_OUTBYTES;

        param[0] = (byte) digestLength;
        param[1] = (byte) keyLength;
        param[2] = (byte) fanout;
        param[3] = (byte) depth;
//        Pack.intToLittleEndian(0, param, 8);
        param[16] = 1; // node depth
        param[17] = (byte) innerHashLength;

        root = new Blake2bDigest(null, param);

        // init leaf
//        param[0] = (byte) digestLength;
        Pack.intToLittleEndian(nodeOffset, param, 8);
        param[16] = 0;  // node depth
        for (int i = 0; i < PARALLELISM_DEGREE; i++)
        {
            Pack.intToLittleEndian(i, param, 8);
            S[i] = new Blake2bDigest(null, param);
        }

        root.setAsLastNode();
        S[PARALLELISM_DEGREE-1].setAsLastNode();

        if(key != null && keyLength > 0)
        {
            byte[] block = new byte[BLAKE2B_BLOCKBYTES];
            System.arraycopy(key, 0, block, 0, keyLength);
            for (int i = 0; i < PARALLELISM_DEGREE; i++)
            {
                S[i].update(block, 0, BLAKE2B_BLOCKBYTES);
            }
        }
    }
}
