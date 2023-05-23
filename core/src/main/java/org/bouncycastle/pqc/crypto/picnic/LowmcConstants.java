package org.bouncycastle.pqc.crypto.picnic;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.Properties;

import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;

abstract class LowmcConstants
{
    protected int[] linearMatrices;
    protected int[] roundConstants;
    protected int[] keyMatrices;

    protected KMatrices LMatrix;
    protected KMatrices KMatrix;
    protected KMatrices RConstants;

    protected int[] linearMatrices_full;
    protected int[] keyMatrices_full;
    protected int[] keyMatrices_inv;
    protected int[] linearMatrices_inv;
    protected int[] roundConstants_full;

    protected KMatrices LMatrix_full;
    protected KMatrices LMatrix_inv;
    protected KMatrices KMatrix_full;
    protected KMatrices KMatrix_inv;
    protected KMatrices RConstants_full;

    static int[] readArray(DataInputStream dIn)
        throws IOException
    {
        int[] rv = new int[dIn.readInt()];
        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = dIn.readInt();
        }
        return rv;
    }

    static int[] ReadFromProperty(Properties props, String key, int intSize)
    {
        String s = props.getProperty(key);
        byte[] bytes = Hex.decode(removeCommas(s));
        int[] ints = new int[intSize];
        for (int i = 0; i < bytes.length / 4; i++)
        {
            ints[i] = Pack.littleEndianToInt(bytes, i * 4);
        }
        return ints;
    }

    private static byte[] removeCommas(String s)
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        for (int i = 0; i != s.length(); i++)
        {
            if (s.charAt(i) == ',')
            {
                continue;
            }
            bOut.write(s.charAt(i));

        }
        return bOut.toByteArray();
    }

    // Functions to return individual matricies and round constants

    /* Return a pointer to the r-th matrix. The caller must know the dimensions */
    private KMatricesWithPointer GET_MAT(KMatrices m, int r)
    {
        KMatricesWithPointer mwp = new KMatricesWithPointer(m);
        mwp.setMatrixPointer(r * mwp.getSize());
        return mwp;
    }


    /* Return the LowMC linear matrix for this round */
    protected KMatricesWithPointer LMatrix(PicnicEngine engine, int round)
    {

        if (engine.stateSizeBits == 128)
        {
            return GET_MAT(LMatrix, round);
        }
        else if (engine.stateSizeBits == 129)
        {
            return GET_MAT(LMatrix_full, round);
        }
        else if (engine.stateSizeBits == 192)
        {
            if (engine.numRounds == 4)
            {
                return GET_MAT(LMatrix_full, round);
            }
            else
            {
                return GET_MAT(LMatrix, round);
            }
        }
        else if (engine.stateSizeBits == 255)
        {
            return GET_MAT(LMatrix_full, round);
        }
        else if (engine.stateSizeBits == 256)
        {
            return GET_MAT(LMatrix, round);
        }
        else
        {
            return null;
        }
    }

    /* Return the LowMC inverse linear layer matrix for this round */
    protected KMatricesWithPointer LMatrixInv(PicnicEngine engine, int round)
    {
        if (engine.stateSizeBits == 129)
        {
            return GET_MAT(LMatrix_inv, round);
        }
        else if (engine.stateSizeBits == 192 && engine.numRounds == 4)
        {
            return GET_MAT(LMatrix_inv, round);
        }
        else if (engine.stateSizeBits == 255)
        {
            return GET_MAT(LMatrix_inv, round);
        }
        else
        {
            return null;
        }
    }

    /* Return the LowMC key matrix for this round */
    protected KMatricesWithPointer KMatrix(PicnicEngine engine, int round)
    {
        if (engine.stateSizeBits == 128)
        {
            return GET_MAT(KMatrix, round);
        }
        else if (engine.stateSizeBits == 129)
        {
            return GET_MAT(KMatrix_full, round);
        }
        else if (engine.stateSizeBits == 192)
        {
            if (engine.numRounds == 4)
            {
                return GET_MAT(KMatrix_full, round);
            }
            else
            {
                return GET_MAT(KMatrix, round);
            }
        }
        else if (engine.stateSizeBits == 255)
        {
            return GET_MAT(KMatrix_full, round);
        }
        else if (engine.stateSizeBits == 256)
        {
            return GET_MAT(KMatrix, round);
        }
        else
        {
            return null;
        }
    }

    /* Return the LowMC inverse key matrix for this round */
    protected KMatricesWithPointer KMatrixInv(PicnicEngine engine)
    {
        int round = 0;
        if (engine.stateSizeBits == 129)
        {
            return GET_MAT(KMatrix_inv, round);
        }
        else if (engine.stateSizeBits == 192 && engine.numRounds == 4)
        {
            return GET_MAT(KMatrix_inv, round);
        }
        else if (engine.stateSizeBits == 255)
        {
            return GET_MAT(KMatrix_inv, round);
        }
        else
        {
            return null;
        }
    }


    /* Return the LowMC round constant for this round */
    protected KMatricesWithPointer RConstant(PicnicEngine engine, int round)
    {
        if (engine.stateSizeBits == 128)
        {
            return GET_MAT(RConstants, round);
        }
        else if (engine.stateSizeBits == 129)
        {
            return GET_MAT(RConstants_full, round);
        }
        else if (engine.stateSizeBits == 192)
        {
            if (engine.numRounds == 4)
            {
                return GET_MAT(RConstants_full, round);
            }
            else
            {
                return GET_MAT(RConstants, round);
            }
        }
        else if (engine.stateSizeBits == 255)
        {
            return GET_MAT(RConstants_full, round);
        }
        else if (engine.stateSizeBits == 256)
        {
            return GET_MAT(RConstants, round);
        }
        else
        {
            return null;
        }
    }
}
