package org.bouncycastle.pqc.crypto.picnic;

import java.io.DataInputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;

import org.bouncycastle.util.Exceptions;

public class LowmcConstantsL1
    extends LowmcConstants
{
    LowmcConstantsL1()
    {
        // load a properties file
        try
        {
            DataInputStream input = new DataInputStream(new GZIPInputStream(LowmcConstants.class.getResourceAsStream("lowmcL1.bin.properties")));

            linearMatrices = readArray(input);
            roundConstants = readArray(input);
            keyMatrices = readArray(input);

            linearMatrices_full = readArray(input);
            keyMatrices_full = readArray(input);
            keyMatrices_inv = readArray(input);
            linearMatrices_inv = readArray(input);
            roundConstants_full = readArray(input);
        }
        catch (IOException e)
        {
            throw Exceptions.illegalStateException("unable to load Picnic properties: " + e.getMessage(), e);
        }

        // Parameters for security level L1
        // Block/key size: 128
        // Rounds: 20
//        linearMatrices = ReadFromProperty(props, "linearMatrices", 40960);
//        roundConstants = ReadFromProperty(props, "roundConstants", 320);
//        keyMatrices = ReadFromProperty(props, "keyMatrices", 43008);

        LMatrix = new KMatrices(20, 128, 4, linearMatrices);
        KMatrix = new KMatrices(21, 128, 4, keyMatrices);
        RConstants = new KMatrices(0, 1, 4, roundConstants);

        // Parameters for security level L1, full s-box layer
        // Block/key size: 129
        // Rounds: 4
        // Note that each 129-bit row of the matrix is zero padded to 160 bits (the next multiple of 32)
//        linearMatrices_full = ReadFromProperty(props, "linearMatrices_full", 12800);
//        keyMatrices_full = ReadFromProperty(props, "keyMatrices_full", 12900);
//        keyMatrices_inv = ReadFromProperty(props, "keyMatrices_inv", 2850);
//        linearMatrices_inv = ReadFromProperty(props, "linearMatrices_inv", 12800);
//        roundConstants_full = ReadFromProperty(props, "roundConstants_full", 80);

        LMatrix_full = new KMatrices(4, 129, 5, linearMatrices_full);
        LMatrix_inv = new KMatrices(4, 129, 5, linearMatrices_inv);
        KMatrix_full = new KMatrices(5, 129, 5, keyMatrices_full);
        KMatrix_inv = new KMatrices(1, 129, 5, keyMatrices_inv);
        RConstants_full = new KMatrices(4, 1, 5, roundConstants_full);

    }
}
