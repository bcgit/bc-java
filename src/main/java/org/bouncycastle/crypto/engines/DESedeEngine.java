package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * a class that provides a basic DESede (or Triple DES) engine.
 */
public class DESedeEngine
    extends DESEngine
{
    protected static final int  BLOCK_SIZE = 8;

    private int[]               workingKey1 = null;
    private int[]               workingKey2 = null;
    private int[]               workingKey3 = null;

    private boolean             forEncryption;

    /**
     * standard constructor.
     */
    public DESedeEngine()
    {
    }

    /**
     * initialise a DESede cipher.
     *
     * @param encrypting whether or not we are for encryption.
     * @param params the parameters required to set up the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     */
    public void init(
        boolean           encrypting,
        CipherParameters  params)
    {
        if (!(params instanceof KeyParameter))
        {
            throw new IllegalArgumentException("invalid parameter passed to DESede init - " + params.getClass().getName());
        }

        byte[] keyMaster = ((KeyParameter)params).getKey();

        if (keyMaster.length != 24 && keyMaster.length != 16)
        {
            // new style 3TDEA key without parity bits.
            if (keyMaster.length == 21)
            {
                byte[] tmp = new byte[24];

                padKey(keyMaster, 0, tmp, 0);
                padKey(keyMaster, 7, tmp, 8);
                padKey(keyMaster, 14, tmp, 16);

                keyMaster = tmp;
            }
            else
            {
                throw new IllegalArgumentException("key size must be 16, 21, or 24 bytes.");
            }
        }

        this.forEncryption = encrypting;

        byte[] key1 = new byte[8];
        System.arraycopy(keyMaster, 0, key1, 0, key1.length);
        workingKey1 = generateWorkingKey(encrypting, key1);

        byte[] key2 = new byte[8];
        System.arraycopy(keyMaster, 8, key2, 0, key2.length);
        workingKey2 = generateWorkingKey(!encrypting, key2);

        if (keyMaster.length == 24)
        {
            byte[] key3 = new byte[8];
            System.arraycopy(keyMaster, 16, key3, 0, key3.length);
            workingKey3 = generateWorkingKey(encrypting, key3);
        }
        else    // 16 byte key
        {
            workingKey3 = workingKey1;
        }
    }

    private void padKey(byte[] keyMaster, int keyOff, byte[] tmp, int tmpOff)
    {
        tmp[tmpOff + 0] = (byte)(keyMaster[keyOff + 0] & 0xfe);
        tmp[tmpOff + 1] = (byte)((keyMaster[keyOff + 0] << 7) | ((keyMaster[keyOff + 1] & 0xfc) >>> 1));
        tmp[tmpOff + 2] = (byte)((keyMaster[keyOff + 1] << 6) | ((keyMaster[keyOff + 2] & 0xf8) >>> 2));
        tmp[tmpOff + 3] = (byte)((keyMaster[keyOff + 2] << 5) | ((keyMaster[keyOff + 3] & 0xf0) >>> 3));
        tmp[tmpOff + 4] = (byte)((keyMaster[keyOff + 3] << 4) | ((keyMaster[keyOff + 4] & 0xe0) >>> 4));
        tmp[tmpOff + 5] = (byte)((keyMaster[keyOff + 4] << 3) | ((keyMaster[keyOff + 5] & 0xc0) >>> 5));
        tmp[tmpOff + 6] = (byte)((keyMaster[keyOff + 5] << 2) | ((keyMaster[keyOff + 6] & 0x80) >>> 6));
        tmp[tmpOff + 7] = (byte)(keyMaster[keyOff + 6] << 1);
    }

    public String getAlgorithmName()
    {
        return "DESede";
    }

    public int getBlockSize()
    {
        return BLOCK_SIZE;
    }

    public int processBlock(
        byte[] in,
        int inOff,
        byte[] out,
        int outOff)
    {
        if (workingKey1 == null)
        {
            throw new IllegalStateException("DESede engine not initialised");
        }

        if ((inOff + BLOCK_SIZE) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        if ((outOff + BLOCK_SIZE) > out.length)
        {
            throw new OutputLengthException("output buffer too short");
        }

        byte[] temp = new byte[BLOCK_SIZE];

        if (forEncryption)
        {
            desFunc(workingKey1, in, inOff, temp, 0);
            desFunc(workingKey2, temp, 0, temp, 0);
            desFunc(workingKey3, temp, 0, out, outOff);
        }
        else
        {
            desFunc(workingKey3, in, inOff, temp, 0);
            desFunc(workingKey2, temp, 0, temp, 0);
            desFunc(workingKey1, temp, 0, out, outOff);
        }

        return BLOCK_SIZE;
    }

    public void reset()
    {
    }
}
