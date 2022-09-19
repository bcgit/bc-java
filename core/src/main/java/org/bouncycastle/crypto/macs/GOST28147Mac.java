package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithSBox;
import org.bouncycastle.util.Pack;

/**
 * implementation of GOST 28147-89 MAC
 */
public class GOST28147Mac
    implements Mac
{
    private final CryptoServicePurpose purpose;
    private static final int    BLOCK_SIZE = 8;
    private static final int    MAC_SIZE = 4;
    private int                 bufOff;
    private byte[]              buf;
    private byte[]              mac;
    private boolean             firstStep = true;
    private int[]               workingKey = null;
    private byte[]              macIV = null;

    //
    // This is default S-box - E_A.
    private byte S[] =
    {
            0x9,0x6,0x3,0x2,0x8,0xB,0x1,0x7,0xA,0x4,0xE,0xF,0xC,0x0,0xD,0x5,
            0x3,0x7,0xE,0x9,0x8,0xA,0xF,0x0,0x5,0x2,0x6,0xC,0xB,0x4,0xD,0x1,
            0xE,0x4,0x6,0x2,0xB,0x3,0xD,0x8,0xC,0xF,0x5,0xA,0x0,0x7,0x1,0x9,
            0xE,0x7,0xA,0xC,0xD,0x1,0x3,0x9,0x0,0x2,0xB,0x4,0xF,0x8,0x5,0x6,
            0xB,0x5,0x1,0x9,0x8,0xD,0xF,0x0,0xE,0x4,0x2,0x3,0xC,0x7,0xA,0x6,
            0x3,0xA,0xD,0xC,0x1,0x2,0x0,0xB,0x7,0x5,0x9,0x4,0x8,0xF,0xE,0x6,
            0x1,0xD,0x2,0x9,0x7,0xA,0x6,0x0,0x8,0xC,0x4,0x5,0xF,0x3,0xB,0xE,
            0xB,0xA,0xF,0x5,0x0,0xC,0xE,0x8,0x6,0x2,0x3,0x9,0x1,0x7,0xD,0x4
    };
    
    public GOST28147Mac()
    {
        this(CryptoServicePurpose.AUTHENTICATION);
    }

    public GOST28147Mac(CryptoServicePurpose purpose)
    {
        this.purpose = purpose;
        mac = new byte[BLOCK_SIZE];

        buf = new byte[BLOCK_SIZE];
        bufOff = 0;
    }

    private int[] generateWorkingKey(
        byte[]  userKey)
    {
        if (userKey.length != 32)
        {
            throw new IllegalArgumentException("Key length invalid. Key needs to be 32 byte - 256 bit!!!");
        }

        int key[] = new int[8];
        for(int i=0; i!=8; i++)
        {
            key[i] = Pack.littleEndianToInt(userKey, i*4);
        }

        return key;
    }
    
    public void init(
        CipherParameters params)
        throws IllegalArgumentException
    {
        reset();
        buf = new byte[BLOCK_SIZE];
        macIV = null;

        recursiveInit(params);

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(getAlgorithmName(), 178, params, purpose));
    }

    private void recursiveInit(
            CipherParameters params)
            throws IllegalArgumentException
    {
        if (params == null)
        {
            return;
        }

        CipherParameters child = null;
        if (params instanceof ParametersWithSBox)
        {
            ParametersWithSBox   param = (ParametersWithSBox)params;

            //
            // Set the S-Box
            //
            System.arraycopy(param.getSBox(), 0, this.S, 0, param.getSBox().length);

            child = param.getParameters();
        }
        else if (params instanceof KeyParameter)
        {
            workingKey = generateWorkingKey(((KeyParameter)params).getKey());
        }
        else if (params instanceof ParametersWithIV)
        {
            ParametersWithIV p = (ParametersWithIV)params;

            System.arraycopy(p.getIV(), 0, mac, 0, mac.length);
            macIV = p.getIV(); // don't skip the initial CM5Func
            child = p.getParameters();
        }
        else
        {
            throw new IllegalArgumentException("invalid parameter passed to GOST28147 init - " + params.getClass().getName());
        }
        recursiveInit(child);
    }

    public String getAlgorithmName()
    {
        return "GOST28147Mac";
    }

    public int getMacSize()
    {
        return MAC_SIZE;
    }

    private int gost28147_mainStep(int n1, int key)
    {
        int cm = (key + n1); // CM1
        
        // S-box replacing
        
        int om = S[  0 + ((cm >> (0 * 4)) & 0xF)] << (0 * 4);
        om += S[ 16 + ((cm >> (1 * 4)) & 0xF)] << (1 * 4);
        om += S[ 32 + ((cm >> (2 * 4)) & 0xF)] << (2 * 4);
        om += S[ 48 + ((cm >> (3 * 4)) & 0xF)] << (3 * 4);
        om += S[ 64 + ((cm >> (4 * 4)) & 0xF)] << (4 * 4);
        om += S[ 80 + ((cm >> (5 * 4)) & 0xF)] << (5 * 4);
        om += S[ 96 + ((cm >> (6 * 4)) & 0xF)] << (6 * 4);
        om += S[112 + ((cm >> (7 * 4)) & 0xF)] << (7 * 4);
        
        return om << 11 | om >>> (32-11); // 11-leftshift
    }
    
    private void gost28147MacFunc(
            int[]   workingKey,
            byte[]  in,
            int     inOff,
            byte[]  out,
            int     outOff)
    {
        int N1 = Pack.littleEndianToInt(in, inOff);
        int N2 = Pack.littleEndianToInt(in, inOff + 4);
        int tmp;  //tmp -> for saving N1
        
        for(int k = 0; k < 2; k++)  // 1-16 steps
        {
            for(int j = 0; j < 8; j++)
            {
                tmp = N1;
                N1 = N2 ^ gost28147_mainStep(N1, workingKey[j]); // CM2
                N2 = tmp;
            }
        }
        
        Pack.intToLittleEndian(N1, out, outOff);
        Pack.intToLittleEndian(N2, out, outOff + 4);
    }

    public void update(byte in)
            throws IllegalStateException
    {
        if (bufOff == buf.length)
        {
            byte[] sum = new byte[buf.length];
            if (firstStep)
            {
                firstStep = false;
                if (macIV != null)
                {
                    CM5func(buf, 0, macIV, sum);
                }
                else
                {
                    System.arraycopy(buf, 0, sum, 0, mac.length);
                }
            }
            else
            {
                CM5func(buf, 0, mac, sum);
            }

            gost28147MacFunc(workingKey, sum, 0, mac, 0);
            bufOff = 0;
        }

        buf[bufOff++] = in;
    }

    public void update(byte[] in, int inOff, int len)
        throws DataLengthException, IllegalStateException
    {
            if (len < 0)
            {
                throw new IllegalArgumentException("Can't have a negative input length!");
            }

            int gapLen = BLOCK_SIZE - bufOff;

            if (len > gapLen)
            {
                System.arraycopy(in, inOff, buf, bufOff, gapLen);

                byte[] sum = new byte[buf.length];
                if (firstStep)
                {
                    firstStep = false;
                    if (macIV != null)
                    {
                        CM5func(buf, 0, macIV, sum);
                    }
                    else
                    {
                        System.arraycopy(buf, 0, sum, 0, mac.length);
                    }
                }
                else
                {
                    CM5func(buf, 0, mac, sum);
                }

                gost28147MacFunc(workingKey, sum, 0, mac, 0);

                bufOff = 0;
                len -= gapLen;
                inOff += gapLen;

                while (len > BLOCK_SIZE)
                {
                    CM5func(in, inOff, mac, sum);
                    gost28147MacFunc(workingKey, sum, 0, mac, 0);

                    len -= BLOCK_SIZE;
                    inOff += BLOCK_SIZE;
                }
            }

            System.arraycopy(in, inOff, buf, bufOff, len);

            bufOff += len;    
    }     

    public int doFinal(byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        //padding with zero
        while (bufOff < BLOCK_SIZE)
        {
            buf[bufOff] = 0;
            bufOff++;
        }

        byte[] sum = new byte[buf.length];
        if (firstStep)
        {
            firstStep = false;
            System.arraycopy(buf, 0, sum, 0, mac.length);
        }
        else
        {
            CM5func(buf, 0, mac, sum);
        }

        gost28147MacFunc(workingKey, sum, 0, mac, 0);

        System.arraycopy(mac, (mac.length/2)-MAC_SIZE, out, outOff, MAC_SIZE);

        reset();

        return MAC_SIZE;
    }

    public void reset()
    {
        /*
         * clean the buffer.
         */
        for (int i = 0; i < buf.length; i++)
        {
            buf[i] = 0;
        }

        bufOff = 0;

        firstStep = true;
    }

    private static void CM5func(byte[] buf, int bufOff, byte[] mac, byte[] sum)
    {
        for (int i = 0; i < BLOCK_SIZE; ++i)
        {
            sum[i] = (byte)(buf[bufOff + i] ^ mac[i]);
        }
    }
}
