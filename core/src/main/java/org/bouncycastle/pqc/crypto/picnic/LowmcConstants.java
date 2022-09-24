package org.bouncycastle.pqc.crypto.picnic;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;

class LowmcConstants
{
    // Parameters for security level L1
    // Block/key size: 128
    // Rounds: 20
    private static final int[] linearMatrices_L1;
    private static final int[] roundConstants_L1;
    private static final int[] keyMatrices_L1;

    private static final KMatrices LMatrix_L1;
    private static final KMatrices KMatrix_L1;
    private static final KMatrices RConstants_L1;

    // Parameters for security level L1, full s-box layer
    // Block/key size: 129
    // Rounds: 4
    // Note that each 129-bit row of the matrix is zero padded to 160 bits (the next multiple of 32)
    private static final int[] linearMatrices_L1_full;
    private static final int[] keyMatrices_L1_full;
    private static final int[] keyMatrices_L1_inv;
    private static final int[] linearMatrices_L1_inv;
    private static final int[] roundConstants_L1_full;

    private static final KMatrices LMatrix_L1_full;
    private static final KMatrices LMatrix_L1_inv;
    private static final KMatrices KMatrix_L1_full;
    private static final KMatrices KMatrix_L1_inv;
    private static final KMatrices RConstants_L1_full;


    // Parameters for security level L3
    // Block/key size: 192
    // Rounds: 30
    private static final int[] linearMatrices_L3;
    private static final int[] roundConstants_L3;
    private static final int[] keyMatrices_L3;

    private static final KMatrices LMatrix_L3;
    private static final KMatrices KMatrix_L3;
    private static final KMatrices RConstants_L3;

    // Parameters for security level L3, full s-box layer
    // Block/key size: 192
    // S-boxes: 64
    // Rounds: 4
    private static final int[] linearMatrices_L3_full;
    private static final int[] linearMatrices_L3_inv;
    private static final int[] roundConstants_L3_full;
    private static final int[] keyMatrices_L3_full;
    private static final int[] keyMatrices_L3_inv;

    private static final KMatrices LMatrix_L3_full;
    private static final KMatrices LMatrix_L3_inv;
    private static final KMatrices KMatrix_L3_full;
    private static final KMatrices KMatrix_L3_inv;
    private static final KMatrices RConstants_L3_full;


    // Parameters for security level L5
    // Block/key size: 256
    // Rounds: 38
    private static final int[] linearMatrices_L5;
    private static final int[] roundConstants_L5;
    private static final int[] keyMatrices_L5;

    private static final KMatrices LMatrix_L5;
    private static final KMatrices KMatrix_L5;
    private static final KMatrices RConstants_L5;

    // Parameters for security level L5, full nonlinear layer
    // Block/key size: 255
    // S-boxes: 85
    // Rounds: 4
    private static final int[] linearMatrices_L5_full;
    private static final int[] linearMatrices_L5_inv;
    private static final int[] roundConstants_L5_full;
    private static final int[] keyMatrices_L5_full;
    private static final int[] keyMatrices_L5_inv;

    private static final KMatrices LMatrix_L5_full;
    private static final KMatrices LMatrix_L5_inv;
    private static final KMatrices KMatrix_L5_full;
    private static final KMatrices KMatrix_L5_inv;
    private static final KMatrices RConstants_L5_full;

    static
    {
        InputStream input = LowmcConstants.class.getResourceAsStream("lowmc.properties");
        Properties props = new Properties();

        // load a properties file
        try
        {
            props.load(input);
        }
        catch (IOException e)
        {
            throw Exceptions.illegalStateException("unable to load Picnic properties: " + e.getMessage(), e);
        }

        // Parameters for security level L1
        // Block/key size: 128
        // Rounds: 20
        linearMatrices_L1 = ReadFromProperty(props, "linearMatrices_L1", 40960);
        roundConstants_L1 = ReadFromProperty(props, "roundConstants_L1", 320);
        keyMatrices_L1 = ReadFromProperty(props, "keyMatrices_L1", 43008);

        LMatrix_L1 = new KMatrices(20, 128, 4, linearMatrices_L1);
        KMatrix_L1 = new KMatrices(21, 128, 4, keyMatrices_L1);
        RConstants_L1 = new KMatrices(0, 1, 4, roundConstants_L1);

        // Parameters for security level L1, full s-box layer
        // Block/key size: 129
        // Rounds: 4
        // Note that each 129-bit row of the matrix is zero padded to 160 bits (the next multiple of 32)
        linearMatrices_L1_full = ReadFromProperty(props, "linearMatrices_L1_full", 12800);
        keyMatrices_L1_full = ReadFromProperty(props, "keyMatrices_L1_full", 12900);
        keyMatrices_L1_inv = ReadFromProperty(props, "keyMatrices_L1_inv", 2850);
        linearMatrices_L1_inv = ReadFromProperty(props, "linearMatrices_L1_inv", 12800);
        roundConstants_L1_full = ReadFromProperty(props, "roundConstants_L1_full", 80);

        LMatrix_L1_full = new KMatrices(4, 129, 5, linearMatrices_L1_full);
        LMatrix_L1_inv = new KMatrices(4, 129, 5, linearMatrices_L1_inv);
        KMatrix_L1_full = new KMatrices(5, 129, 5, keyMatrices_L1_full);
        KMatrix_L1_inv = new KMatrices(1, 129, 5, keyMatrices_L1_inv);
        RConstants_L1_full = new KMatrices(4, 1, 5, roundConstants_L1_full);


        // Parameters for security level L3
        // Block/key size: 192
        // Rounds: 30
        linearMatrices_L3 = ReadFromProperty(props, "linearMatrices_L3", 138240);
        roundConstants_L3 = ReadFromProperty(props, "roundConstants_L3", 720);
        keyMatrices_L3 = ReadFromProperty(props, "keyMatrices_L3", 142848);

        LMatrix_L3 = new KMatrices(30, 192, 6, linearMatrices_L3);
        KMatrix_L3 = new KMatrices(31, 192, 6, keyMatrices_L3);
        RConstants_L3 = new KMatrices(30, 1, 6, roundConstants_L3);

        // Parameters for security level L3, full s-box layer
        // Block/key size: 192
        // S-boxes: 64
        // Rounds: 4
        linearMatrices_L3_full = ReadFromProperty(props, "linearMatrices_L3_full", 18432);
        linearMatrices_L3_inv = ReadFromProperty(props, "linearMatrices_L3_inv", 18432);
        roundConstants_L3_full = ReadFromProperty(props, "roundConstants_L3_full", 96);
        keyMatrices_L3_full = ReadFromProperty(props, "keyMatrices_L3_full", 23040);
        keyMatrices_L3_inv = ReadFromProperty(props, "keyMatrices_L3_inv", 4608);

        LMatrix_L3_full = new KMatrices(4, 192, 6, linearMatrices_L3_full);
        LMatrix_L3_inv = new KMatrices(4, 192, 6, linearMatrices_L3_inv);
        KMatrix_L3_full = new KMatrices(5, 192, 6, keyMatrices_L3_full);
        KMatrix_L3_inv = new KMatrices(1, 192, 6, keyMatrices_L3_inv);
        RConstants_L3_full = new KMatrices(4, 1, 6, roundConstants_L3_full);


        // Parameters for security level L5
        // Block/key size: 256
        // Rounds: 38
        linearMatrices_L5 = ReadFromProperty(props, "linearMatrices_L5", 311296);
        roundConstants_L5 = ReadFromProperty(props, "roundConstants_L5", 1216);
        keyMatrices_L5 = ReadFromProperty(props, "keyMatrices_L5", 319488);

        LMatrix_L5 = new KMatrices(38, 256, 8, linearMatrices_L5);
        KMatrix_L5 = new KMatrices(39, 256, 8, keyMatrices_L5);
        RConstants_L5 = new KMatrices(38, 1, 8, roundConstants_L5);

        // Parameters for security level L5, full nonlinear layer
        // Block/key size: 255
        // S-boxes: 85
        // Rounds: 4
        linearMatrices_L5_full = ReadFromProperty(props, "linearMatrices_L5_full", 32768);
        linearMatrices_L5_inv = ReadFromProperty(props, "linearMatrices_L5_inv", 32768);
        roundConstants_L5_full = ReadFromProperty(props, "roundConstants_L5_full", 128);
        keyMatrices_L5_full = ReadFromProperty(props, "keyMatrices_L5_full", 40960);
        keyMatrices_L5_inv = ReadFromProperty(props, "keyMatrices_L5_inv", 8160);

        LMatrix_L5_full = new KMatrices(4, 255, 8, linearMatrices_L5_full);
        LMatrix_L5_inv = new KMatrices(4, 255, 8, linearMatrices_L5_inv);
        KMatrix_L5_full = new KMatrices(5, 255, 8, keyMatrices_L5_full);
        KMatrix_L5_inv = new KMatrices(1, 255, 8, keyMatrices_L5_inv);
        RConstants_L5_full = new KMatrices(4, 1, 8, roundConstants_L5_full);
    }

    static private int[] ReadFromProperty(Properties props, String key, int intSize)
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
    private static KMatricesWithPointer GET_MAT(KMatrices m, int r)
    {
        KMatricesWithPointer mwp = new KMatricesWithPointer(m);
        mwp.setMatrixPointer(r * mwp.getSize());
        return mwp;
    }


    /* Return the LowMC linear matrix for this round */
    static KMatricesWithPointer LMatrix(PicnicEngine engine, int round)
    {

        if (engine.stateSizeBits == 128)
        {
            return GET_MAT(LMatrix_L1, round);
        }
        else if (engine.stateSizeBits == 129)
        {
            return GET_MAT(LMatrix_L1_full, round);
        }
        else if (engine.stateSizeBits == 192)
        {
            if (engine.numRounds == 4)
            {
                return GET_MAT(LMatrix_L3_full, round);
            }
            else
            {
                return GET_MAT(LMatrix_L3, round);
            }
        }
        else if (engine.stateSizeBits == 255)
        {
            return GET_MAT(LMatrix_L5_full, round);
        }
        else if (engine.stateSizeBits == 256)
        {
            return GET_MAT(LMatrix_L5, round);
        }
        else
        {
            return null;
        }
    }

    /* Return the LowMC inverse linear layer matrix for this round */
    static KMatricesWithPointer LMatrixInv(PicnicEngine engine, int round)
    {
        if (engine.stateSizeBits == 129)
        {
            return GET_MAT(LMatrix_L1_inv, round);
        }
        else if (engine.stateSizeBits == 192 && engine.numRounds == 4)
        {
            return GET_MAT(LMatrix_L3_inv, round);
        }
        else if (engine.stateSizeBits == 255)
        {
            return GET_MAT(LMatrix_L5_inv, round);
        }
        else
        {
            return null;
        }
    }

    /* Return the LowMC key matrix for this round */
    static KMatricesWithPointer KMatrix(PicnicEngine engine, int round)
    {
        if (engine.stateSizeBits == 128)
        {
            return GET_MAT(KMatrix_L1, round);
        }
        else if (engine.stateSizeBits == 129)
        {
            return GET_MAT(KMatrix_L1_full, round);
        }
        else if (engine.stateSizeBits == 192)
        {
            if (engine.numRounds == 4)
            {
                return GET_MAT(KMatrix_L3_full, round);
            }
            else
            {
                return GET_MAT(KMatrix_L3, round);
            }
        }
        else if (engine.stateSizeBits == 255)
        {
            return GET_MAT(KMatrix_L5_full, round);
        }
        else if (engine.stateSizeBits == 256)
        {
            return GET_MAT(KMatrix_L5, round);
        }
        else
        {
            return null;
        }
    }

    /* Return the LowMC inverse key matrix for this round */
    static KMatricesWithPointer KMatrixInv(PicnicEngine engine)
    {
        int round = 0;
        if (engine.stateSizeBits == 129)
        {
            return GET_MAT(KMatrix_L1_inv, round);
        }
        else if (engine.stateSizeBits == 192 && engine.numRounds == 4)
        {
            return GET_MAT(KMatrix_L3_inv, round);
        }
        else if (engine.stateSizeBits == 255)
        {
            return GET_MAT(KMatrix_L5_inv, round);
        }
        else
        {
            return null;
        }
    }


    /* Return the LowMC round constant for this round */
    static KMatricesWithPointer RConstant(PicnicEngine engine, int round)
    {
        if (engine.stateSizeBits == 128)
        {
            return GET_MAT(RConstants_L1, round);
        }
        else if (engine.stateSizeBits == 129)
        {
            return GET_MAT(RConstants_L1_full, round);
        }
        else if (engine.stateSizeBits == 192)
        {
            if (engine.numRounds == 4)
            {
                return GET_MAT(RConstants_L3_full, round);
            }
            else
            {
                return GET_MAT(RConstants_L3, round);
            }
        }
        else if (engine.stateSizeBits == 255)
        {
            return GET_MAT(RConstants_L5_full, round);
        }
        else if (engine.stateSizeBits == 256)
        {
            return GET_MAT(RConstants_L5, round);
        }
        else
        {
            return null;
        }
    }


}
