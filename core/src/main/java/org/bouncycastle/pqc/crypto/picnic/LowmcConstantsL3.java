package org.bouncycastle.pqc.crypto.picnic;

import java.io.DataInputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;

import org.bouncycastle.util.Exceptions;

public class LowmcConstantsL3
    extends LowmcConstants
{
    LowmcConstantsL3()
    {
        // load a properties file
        try
        {
            DataInputStream input = new DataInputStream(new GZIPInputStream(LowmcConstants.class.getResourceAsStream("lowmcL3.bin.properties")));

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

        // Parameters for security level L3
        // Block/key size: 192
        // Rounds: 30
//        linearMatrices = ReadFromProperty(props, "linearMatrices", 138240);
//        roundConstants = ReadFromProperty(props, "roundConstants", 720);
//        keyMatrices = ReadFromProperty(props, "keyMatrices", 142848);

        LMatrix = new KMatrices(30, 192, 6, linearMatrices);
        KMatrix = new KMatrices(31, 192, 6, keyMatrices);
        RConstants = new KMatrices(30, 1, 6, roundConstants);

        // Parameters for security level L3, full s-box layer
        // Block/key size: 192
        // S-boxes: 64
        // Rounds: 4
//        linearMatrices_full = ReadFromProperty(props, "linearMatrices_full", 18432);
//        linearMatrices_inv = ReadFromProperty(props, "linearMatrices_inv", 18432);
//        roundConstants_full = ReadFromProperty(props, "roundConstants_full", 96);
//        keyMatrices_full = ReadFromProperty(props, "keyMatrices_full", 23040);
//        keyMatrices_inv = ReadFromProperty(props, "keyMatrices_inv", 4608);

        LMatrix_full = new KMatrices(4, 192, 6, linearMatrices_full);
        LMatrix_inv = new KMatrices(4, 192, 6, linearMatrices_inv);
        KMatrix_full = new KMatrices(5, 192, 6, keyMatrices_full);
        KMatrix_inv = new KMatrices(1, 192, 6, keyMatrices_inv);
        RConstants_full = new KMatrices(4, 1, 6, roundConstants_full);
    }
}