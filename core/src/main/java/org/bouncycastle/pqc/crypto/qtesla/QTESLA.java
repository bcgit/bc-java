package org.bouncycastle.pqc.crypto.qtesla;

import java.security.SecureRandom;
import java.util.Arrays;

class QTESLA
{

    /********************************************************************************************************************************************
     * Description:	Pack Private Key for Heuristic qTESLA Security Category-1 and Category-3 (Option for Size or Speed)
     *
     * @param        privateKey                Private Key
     * @param        secretPolynomial        Coefficients of the Secret Polynomials
     * @param        errorPolynomial            Coefficients of the Error Polynomials
     * @param        seed                    Kappa-Bit Seed
     * @param        seedOffset                Starting Point of the Kappa-Bit Seed
     * @param        n                        Polynomial Degree
     *
     * @return none
     ********************************************************************************************************************************************/
    private static void packPrivateKey(byte[] privateKey, long[] secretPolynomial, long[] errorPolynomial, byte[] seed, int seedOffset, int n)
    {

        for (int i = 0; i < n * Short.SIZE / Byte.SIZE; i += Short.SIZE / Byte.SIZE)
        {

            CommonFunction.store16(privateKey, i, (short)secretPolynomial[i / (Short.SIZE / Byte.SIZE)]);

        }

        for (int i = 0; i < n * Short.SIZE / Byte.SIZE; i += Short.SIZE / Byte.SIZE)
        {

            CommonFunction.store16(privateKey, i + n * Short.SIZE / Byte.SIZE, (short)errorPolynomial[i / (Short.SIZE / Byte.SIZE)]);

        }

        System.arraycopy(seed, seedOffset, privateKey, n * Short.SIZE / Byte.SIZE * 2, Polynomial.RANDOM * 2);

    }

    /*****************************************************************************************************************************************************
     * Description:	Pack Private Key for Provably-Secure qTESLA Security Category-1 and Category-3
     *
     * @param        privateKey                Private Key
     * @param        secretPolynomial        Coefficients of the Secret Polynomials
     * @param        errorPolynomial            Coefficients of the Error Polynomials
     * @param        seed                    Kappa-Bit Seed
     * @param        seedOffset                Starting Point of the Kappa-Bit Seed
     * @param        n                        Polynomial Degree
     * @param        k                        Number of Ring-Learning-With-Errors Samples
     *
     * @return none
     *****************************************************************************************************************************************************/
    private static void packPrivateKey(byte[] privateKey, long[] secretPolynomial, long[] errorPolynomial, byte[] seed, int seedOffset, int n, int k)
    {

        for (int i = 0; i < n; i++)
        {

            privateKey[i] = (byte)secretPolynomial[i];

        }

        for (int j = 0; j < k; j++)
        {

            for (short i = 0; i < n; i++)
            {

                privateKey[n + j * n + i] = (byte)errorPolynomial[j * n + i];

            }

        }

        System.arraycopy(seed, seedOffset, privateKey, n * (k + 1), Polynomial.SEED * 2);

    }

    /********************************************************************************************************************************************
     * Description:	Encode Public Key for Heuristic qTESLA Security Category-1 and Category-3 (Option for Size)
     *
     * @param        publicKey            Public Key
     * @param        T                    T_1, ..., T_k
     * @param        seedA                Seed Used to Generate the Polynomials a_i for i = 1, ..., k
     * @param        seedAOffset            Starting Point of the Seed A
     * @param        n                    Polynomial Degree
     * @param        qLogarithm            q <= 2 ^ qLogartihm
     *
     * @return none
     ********************************************************************************************************************************************/
    private static void encodePublicKey(byte[] publicKey, final long[] T, final byte[] seedA, int seedAOffset, int n, int qLogarithm)
    {

        int j = 0;

        for (int i = 0; i < n * qLogarithm / Integer.SIZE; i += qLogarithm)
        {

            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 0), (int)(T[j + 0] | (T[j + 1] << 23)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 1), (int)((T[j + 1] >> 9) | (T[j + 2] << 14)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 2), (int)((T[j + 2] >> 18) | (T[j + 3] << 5) | (T[j + 4] << 28)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 3), (int)((T[j + 4] >> 4) | (T[j + 5] << 19)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 4), (int)((T[j + 5] >> 13) | (T[j + 6] << 10)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 5), (int)((T[j + 6] >> 22) | (T[j + 7] << 1) | (T[j + 8] << 24)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 6), (int)((T[j + 8] >> 8) | (T[j + 9] << 15)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 7), (int)((T[j + 9] >> 17) | (T[j + 10] << 6) | (T[j + 11] << 29)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 8), (int)((T[j + 11] >> 3) | (T[j + 12] << 20)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 9), (int)((T[j + 12] >> 12) | (T[j + 13] << 11)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 10), (int)((T[j + 13] >> 21) | (T[j + 14] << 2) | (T[j + 15] << 25)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 11), (int)((T[j + 15] >> 7) | (T[j + 16] << 16)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 12), (int)((T[j + 16] >> 16) | (T[j + 17] << 7) | (T[j + 18] << 30)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 13), (int)((T[j + 18] >> 2) | (T[j + 19] << 21)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 14), (int)((T[j + 19] >> 11) | (T[j + 20] << 12)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 15), (int)((T[j + 20] >> 20) | (T[j + 21] << 3) | (T[j + 22] << 26)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 16), (int)((T[j + 22] >> 6) | (T[j + 23] << 17)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 17), (int)((T[j + 23] >> 15) | (T[j + 24] << 8) | (T[j + 25] << 31)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 18), (int)((T[j + 25] >> 1) | (T[j + 26] << 22)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 19), (int)((T[j + 26] >> 10) | (T[j + 27] << 13)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 20), (int)((T[j + 27] >> 19) | (T[j + 28] << 4) | (T[j + 29] << 27)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 21), (int)((T[j + 29] >> 5) | (T[j + 30] << 18)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 22), (int)((T[j + 30] >> 14) | (T[j + 31] << 9)));

            j += Integer.SIZE;

        }

        System.arraycopy(seedA, seedAOffset, publicKey, n * qLogarithm / Byte.SIZE, Polynomial.SEED);

    }

    /******************************************************************************************************************************************************
     * Description:	Encode Public Key for Heuristic qTESLA Security Category-3 (Option for Speed)
     *
     * @param        publicKey            Public Key
     * @param        T                    T_1, ..., T_k
     * @param        seedA                Seed Used to Generate the Polynomials a_i for i = 1, ..., k
     * @param        seedAOffset            Starting Point of the Seed A
     *
     * @return none
     ******************************************************************************************************************************************************/
    private static void encodePublicKeyIIISpeed(byte[] publicKey, final long[] T, final byte[] seedA, int seedAOffset)
    {

        int j = 0;

        for (int i = 0; i < Parameter.N_III_SPEED * Parameter.Q_LOGARITHM_III_SPEED / Integer.SIZE; i += (Parameter.Q_LOGARITHM_III_SPEED / Byte.SIZE))
        {

            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 0), (int)(T[j + 0] | (T[j + 1] << 24)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 1), (int)((T[j + 1] >> 8) | (T[j + 2] << 16)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 2), (int)((T[j + 2] >> 16) | (T[j + 3] << 8)));

            j += Integer.SIZE / Byte.SIZE;

        }

        System.arraycopy(seedA, seedAOffset, publicKey, Parameter.N_III_SPEED * Parameter.Q_LOGARITHM_III_SPEED / Byte.SIZE, Polynomial.SEED);

    }

    /*******************************************************************************************************************************************************
     * Description:	Encode Public Key for Provably-Secure qTESLA Security Category-1
     *
     * @param        publicKey            Public Key
     * @param        T                    T_1, ..., T_k
     * @param        seedA                Seed Used to Generate the Polynomials a_i for i = 1, ..., k
     * @param        seedAOffset            Starting Point of the Seed A
     *
     * @return none
     *******************************************************************************************************************************************************/
    private static void encodePublicKeyIP(byte[] publicKey, final long[] T, final byte[] seedA, int seedAOffset)
    {

        int j = 0;

        for (int i = 0; i < Parameter.N_I_P * Parameter.K_I_P * Parameter.Q_LOGARITHM_I_P / Integer.SIZE; i += Parameter.Q_LOGARITHM_I_P)
        {

            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 0), (int)(T[j + 0] | (T[j + 1] << 29)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 1), (int)((T[j + 1] >> 3) | (T[j + 2] << 26)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 2), (int)((T[j + 2] >> 6) | (T[j + 3] << 23)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 3), (int)((T[j + 3] >> 9) | (T[j + 4] << 20)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 4), (int)((T[j + 4] >> 12) | (T[j + 5] << 17)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 5), (int)((T[j + 5] >> 15) | (T[j + 6] << 14)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 6), (int)((T[j + 6] >> 18) | (T[j + 7] << 11)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 7), (int)((T[j + 7] >> 21) | (T[j + 8] << 8)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 8), (int)((T[j + 8] >> 24) | (T[j + 9] << 5)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 9), (int)((T[j + 9] >> 27) | (T[j + 10] << 2) | (T[j + 11] << 31)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 10), (int)((T[j + 11] >> 1) | (T[j + 12] << 28)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 11), (int)((T[j + 12] >> 4) | (T[j + 13] << 25)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 12), (int)((T[j + 13] >> 7) | (T[j + 14] << 22)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 13), (int)((T[j + 14] >> 10) | (T[j + 15] << 19)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 14), (int)((T[j + 15] >> 13) | (T[j + 16] << 16)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 15), (int)((T[j + 16] >> 16) | (T[j + 17] << 13)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 16), (int)((T[j + 17] >> 19) | (T[j + 18] << 10)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 17), (int)((T[j + 18] >> 22) | (T[j + 19] << 7)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 18), (int)((T[j + 19] >> 25) | (T[j + 20] << 4)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 19), (int)((T[j + 20] >> 28) | (T[j + 21] << 1) | (T[j + 22] << 30)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 20), (int)((T[j + 22] >> 2) | (T[j + 23] << 27)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 21), (int)((T[j + 23] >> 5) | (T[j + 24] << 24)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 22), (int)((T[j + 24] >> 8) | (T[j + 25] << 21)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 23), (int)((T[j + 25] >> 11) | (T[j + 26] << 18)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 24), (int)((T[j + 26] >> 14) | (T[j + 27] << 15)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 25), (int)((T[j + 27] >> 17) | (T[j + 28] << 12)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 26), (int)((T[j + 28] >> 20) | (T[j + 29] << 9)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 27), (int)((T[j + 29] >> 23) | (T[j + 30] << 6)));
            CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + 28), (int)((T[j + 30] >> 26) | (T[j + 31] << 3)));

            j += Integer.SIZE;

        }

        System.arraycopy(seedA, seedAOffset, publicKey, Parameter.N_I_P * Parameter.K_I_P * Parameter.Q_LOGARITHM_I_P / Byte.SIZE, Polynomial.SEED);

    }

    /******************************************************************************************************************************************************************************
     * Description:	Encode Public Key for Provably-Secure qTESLA Security Category-3
     *
     * @param        publicKey            Public Key
     * @param        T                    T_1, ..., T_k
     * @param        seedA                Seed Used to Generate the Polynomials a_i for i = 1, ..., k
     * @param        seedAOffset            Starting Point of the Seed A
     *
     * @return none
     ******************************************************************************************************************************************************************************/
    private static void encodePublicKeyIIIP(byte[] publicKey, final long[] T, final byte[] seedA, int seedAOffset)
    {
        int j = 0;

        for (int i = 0; i < Parameter.N_III_P * Parameter.K_III_P * Parameter.Q_LOGARITHM_III_P / Integer.SIZE; i += Parameter.Q_LOGARITHM_III_P)
        {
            for (int index = 0; index < Parameter.Q_LOGARITHM_III_P; index++)
            {

                CommonFunction.store32(publicKey, Integer.SIZE / Byte.SIZE * (i + index), (int)((T[j + index] >>> index) | (T[j + index + 1] << (Parameter.Q_LOGARITHM_III_P - index))));

            }

            j += Integer.SIZE;
        }

        System.arraycopy(seedA, seedAOffset, publicKey, Parameter.N_III_P * Parameter.K_III_P * Parameter.Q_LOGARITHM_III_P / Byte.SIZE, Polynomial.SEED);
    }

    /*********************************************************************************************************************************************
     * Description:	Decode Public Key for Heuristic qTESLA Security Category-1 and Category-3 (Option for Size)
     *
     * @param        publicKey            Decoded Public Key
     * @param        seedA                Seed Used to Generate the Polynomials A_i for i = 1, ..., k
     * @param        seedAOffset            Starting Point of the Seed A
     * @param        publicKeyInput        Public Key to be Decoded
     * @param        n                    Polynomial Degree
     * @param        qLogarithm            q <= 2 ^ qLogartihm
     *
     * @return none
     *********************************************************************************************************************************************/
    private static void decodePublicKey(int[] publicKey, byte[] seedA, int seedAOffset, final byte[] publicKeyInput, int n, int qLogarithm)
    {

        int j = 0;

        int mask = (1 << qLogarithm) - 1;

        for (int i = 0; i < n; i += Integer.SIZE)
        {

            publicKey[i + 0] = CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 0)) & mask;

            publicKey[i + 1] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 0)) >>> 23) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 1)) << 9)) & mask;

            publicKey[i + 2] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 1)) >>> 14) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 2)) << 18)) & mask;

            publicKey[i + 3] = (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 2)) >>> 5) & mask;

            publicKey[i + 4] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 2)) >>> 28) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 3)) << 4)) & mask;

            publicKey[i + 5] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 3)) >>> 19) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 4)) << 13)) & mask;

            publicKey[i + 6] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 4)) >>> 10) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 5)) << 22)) & mask;

            publicKey[i + 7] = (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 5)) >>> 1) & mask;

            publicKey[i + 8] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 5)) >>> 24) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 6)) << 8)) & mask;

            publicKey[i + 9] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 6)) >>> 15) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 7)) << 17)) & mask;

            publicKey[i + 10] = (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 7)) >>> 6) & mask;

            publicKey[i + 11] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 7)) >>> 29) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 8)) << 3)) & mask;

            publicKey[i + 12] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 8)) >>> 20) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 9)) << 12)) & mask;

            publicKey[i + 13] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 9)) >>> 11) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 10)) << 21)) & mask;

            publicKey[i + 14] = (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 10)) >>> 2) & mask;

            publicKey[i + 15] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 10)) >>> 25) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 11)) << 7)) & mask;

            publicKey[i + 16] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 11)) >>> 16) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 12)) << 16)) & mask;

            publicKey[i + 17] = (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 12)) >>> 7) & mask;

            publicKey[i + 18] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 12)) >>> 30) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 13)) << 2)) & mask;

            publicKey[i + 19] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 13)) >>> 21) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 14)) << 11)) & mask;

            publicKey[i + 20] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 14)) >>> 12) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 15)) << 20)) & mask;

            publicKey[i + 21] = (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 15)) >>> 3) & mask;

            publicKey[i + 22] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 15)) >>> 26) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 16)) << 6)) & mask;

            publicKey[i + 23] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 16)) >>> 17) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 17)) << 15)) & mask;

            publicKey[i + 24] = (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 17)) >>> 8) & mask;

            publicKey[i + 25] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 17)) >>> 31) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 18)) << 1)) & mask;

            publicKey[i + 26] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 18)) >>> 22) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 19)) << 10)) & mask;

            publicKey[i + 27] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 19)) >>> 13) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 20)) << 19)) & mask;

            publicKey[i + 28] = (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 20)) >>> 4) & mask;

            publicKey[i + 29] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 20)) >>> 27) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 21)) << 5)) & mask;

            publicKey[i + 30] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 21)) >>> 18) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 22)) << 14)) & mask;

            publicKey[i + 31] = CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 22)) >>> 9;

            j += qLogarithm;

        }

        System.arraycopy(publicKeyInput, (n * qLogarithm) / Byte.SIZE, seedA, seedAOffset, Polynomial.SEED);

    }

    /******************************************************************************************************************************************************
     * Description:	Decode Public Key for Heuristic qTESLA Security Category-3 (Option for Speed)
     *
     * @param        publicKey            Decoded Public Key
     * @param        seedA                Seed Used to Generate the Polynomials A_i for i = 1, ..., k
     * @param        seedAOffset            Starting Point of the Seed A
     * @param        publicKeyInput        Public Key to be Decoded
     *
     * @return none
     ******************************************************************************************************************************************************/
    private static void decodePublicKeyIIISpeed(int[] publicKey, byte[] seedA, int seedAOffset, final byte[] publicKeyInput)
    {

        int j = 0;

        int mask = (1 << Parameter.Q_LOGARITHM_III_SPEED) - 1;

        for (int i = 0; i < Parameter.N_III_SPEED; i += Integer.SIZE / Byte.SIZE)
        {

            publicKey[i + 0] = CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 0)) & mask;

            publicKey[i + 1] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 0)) >>> 24) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 1)) << 8)) & mask;

            publicKey[i + 2] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 1)) >>> 16) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 2)) << 16)) & mask;

            publicKey[i + 3] = CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 2)) >>> 8;

            j += Parameter.Q_LOGARITHM_III_SPEED / Byte.SIZE;

        }

        System.arraycopy(publicKeyInput, Parameter.N_III_SPEED * Parameter.Q_LOGARITHM_III_SPEED / Byte.SIZE, seedA, seedAOffset, Polynomial.SEED);

    }

    /************************************************************************************************************************************************************
     * Description:	Decode Public Key for Provably-Secure qTESLA Security Category-1
     *
     * @param        publicKey            Decoded Public Key
     * @param        seedA                Seed Used to Generate the Polynomials A_i for i = 1, ..., k
     * @param        seedAOffset            Starting Point of the Seed A
     * @param        publicKeyInput        Public Key to be Decoded
     *
     * @return none
     ************************************************************************************************************************************************************/
    private static void decodePublicKeyIP(int[] publicKey, byte[] seedA, int seedAOffset, final byte[] publicKeyInput)
    {

        int j = 0;

        int mask = (1 << Parameter.Q_LOGARITHM_I_P) - 1;

        for (int i = 0; i < Parameter.N_I_P * Parameter.K_I_P; i += Integer.SIZE)
        {

            publicKey[i + 0] = CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 0)) & mask;

            publicKey[i + 1] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 0)) >>> 29) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 1)) << 3)) & mask;

            publicKey[i + 2] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 1)) >>> 26) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 2)) << 6)) & mask;

            publicKey[i + 3] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 2)) >>> 23) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 3)) << 9)) & mask;

            publicKey[i + 4] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 3)) >>> 20) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 4)) << 12)) & mask;

            publicKey[i + 5] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 4)) >>> 17) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 5)) << 15)) & mask;

            publicKey[i + 6] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 5)) >>> 14) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 6)) << 18)) & mask;

            publicKey[i + 7] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 6)) >>> 11) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 7)) << 21)) & mask;

            publicKey[i + 8] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 7)) >>> 8) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 8)) << 24)) & mask;

            publicKey[i + 9] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 8)) >>> 5) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 9)) << 27)) & mask;

            publicKey[i + 10] = (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 9)) >>> 2) & mask;

            publicKey[i + 11] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 9)) >>> 31) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 10)) << 1)) & mask;

            publicKey[i + 12] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 10)) >>> 28) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 11)) << 4)) & mask;

            publicKey[i + 13] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 11)) >>> 25) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 12)) << 7)) & mask;

            publicKey[i + 14] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 12)) >>> 22) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 13)) << 10)) & mask;

            publicKey[i + 15] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 13)) >>> 19) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 14)) << 13)) & mask;

            publicKey[i + 16] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 14)) >>> 16) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 15)) << 16)) & mask;

            publicKey[i + 17] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 15)) >>> 13) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 16)) << 19)) & mask;

            publicKey[i + 18] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 16)) >>> 10) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 17)) << 22)) & mask;

            publicKey[i + 19] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 17)) >>> 7) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 18)) << 25)) & mask;

            publicKey[i + 20] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 18)) >>> 4) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 19)) << 28)) & mask;

            publicKey[i + 21] = (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 19)) >>> 1) & mask;

            publicKey[i + 22] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 19)) >>> 30) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 20)) << 2)) & mask;

            publicKey[i + 23] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 20)) >>> 27) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 21)) << 5)) & mask;

            publicKey[i + 24] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 21)) >>> 24) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 22)) << 8)) & mask;

            publicKey[i + 25] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 22)) >>> 21) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 23)) << 11)) & mask;

            publicKey[i + 26] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 23)) >>> 18) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 24)) << 14)) & mask;

            publicKey[i + 27] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 24)) >>> 15) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 25)) << 17)) & mask;

            publicKey[i + 28] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 25)) >>> 12) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 26)) << 20)) & mask;

            publicKey[i + 29] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 26)) >>> 9) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 27)) << 23)) & mask;

            publicKey[i + 30] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 27)) >>> 6) |
                (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 28)) << 26)) & mask;

            publicKey[i + 31] = CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 28)) >>> 3;

            j += Parameter.Q_LOGARITHM_I_P;

        }

        System.arraycopy(publicKeyInput, Parameter.N_I_P * Parameter.K_I_P * Parameter.Q_LOGARITHM_I_P / Byte.SIZE, seedA, seedAOffset, Polynomial.SEED);

    }

    /****************************************************************************************************************************************************************
     * Description:	Decode Public Key for Provably-Secure qTESLA Security Category-3
     *
     * @param        publicKey            Decoded Public Key
     * @param        seedA                Seed Used to Generate the Polynomials A_i for i = 1, ..., k
     * @param        seedAOffset            Starting Point of the Seed A
     * @param        publicKeyInput        Public Key to be Decoded
     *
     * @return none
     ****************************************************************************************************************************************************************/
    private static void decodePublicKeyIIIP(int[] publicKey, byte[] seedA, int seedAOffset, final byte[] publicKeyInput)
    {

        int j = 0;

        int mask = (1 << Parameter.Q_LOGARITHM_III_P) - 1;

        for (short i = 0; i < Parameter.N_III_P * Parameter.K_III_P; i += Integer.SIZE)
        {

            publicKey[i] = CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * j) & mask;

            for (int index = 1; index < Parameter.Q_LOGARITHM_III_P; index++)
            {

                publicKey[i + index] = ((CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + index - 1)) >>> (Integer.SIZE - index)) |
                    (CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + index)) << index)) & mask;

            }

            publicKey[i + Parameter.Q_LOGARITHM_III_P] = CommonFunction.load32(publicKeyInput, Integer.SIZE / Byte.SIZE * (j + Parameter.Q_LOGARITHM_III_P - 1)) >>> 1;

            j += Parameter.Q_LOGARITHM_III_P;

        }

        System.arraycopy(publicKeyInput, Parameter.N_III_P * Parameter.K_III_P * Parameter.Q_LOGARITHM_III_P / Byte.SIZE, seedA, seedAOffset, Polynomial.SEED);

    }

    /********************************************************************************************************************************************************************************************************
     * Description:	Encode Signature for Heuristic qTESLA Security Category-1 and Category-3 (Option for Size)
     ********************************************************************************************************************************************************************************************************/
    private static void encodeSignature(byte[] signature, int signatureOffset, byte[] C, int cOffset, long[] Z, int n, int d)
    {

        int j = 0;

        for (int i = 0; i < (n * d / Integer.SIZE); i += d)
        {

            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 0), (int)(((Z[j + 0] & ((1 << 21) - 1))) | (Z[j + 1] << 21)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 1), (int)(((Z[j + 1] >>> 11) & ((1 << 10) - 1)) | ((Z[j + 2] & ((1 << 21) - 1)) << 10) | (Z[j + 3] << 31)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 2), (int)((((Z[j + 3] >>> 1) & ((1 << 20) - 1))) | (Z[j + 4] << 20)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 3), (int)(((Z[j + 4] >>> 12) & ((1 << 9) - 1)) | ((Z[j + 5] & ((1 << 21) - 1)) << 9) | (Z[j + 6] << 30)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 4), (int)((((Z[j + 6] >>> 2) & ((1 << 19) - 1))) | (Z[j + 7] << 19)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 5), (int)(((Z[j + 7] >>> 13) & ((1 << 8) - 1)) | ((Z[j + 8] & ((1 << 21) - 1)) << 8) | (Z[j + 9] << 29)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 6), (int)((((Z[j + 9] >>> 3) & ((1 << 18) - 1))) | (Z[j + 10] << 18)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 7), (int)(((Z[j + 10] >>> 14) & ((1 << 7) - 1)) | ((Z[j + 11] & ((1 << 21) - 1)) << 7) | (Z[j + 12] << 28)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 8), (int)((((Z[j + 12] >>> 4) & ((1 << 17) - 1))) | (Z[j + 13] << 17)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 9), (int)(((Z[j + 13] >>> 15) & ((1 << 6) - 1)) | ((Z[j + 14] & ((1 << 21) - 1)) << 6) | (Z[j + 15] << 27)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 10), (int)((((Z[j + 15] >>> 5) & ((1 << 16) - 1))) | (Z[j + 16] << 16)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 11), (int)(((Z[j + 16] >>> 16) & ((1 << 5) - 1)) | ((Z[j + 17] & ((1 << 21) - 1)) << 5) | (Z[j + 18] << 26)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 12), (int)((((Z[j + 18] >>> 6) & ((1 << 15) - 1))) | (Z[j + 19] << 15)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 13), (int)(((Z[j + 19] >>> 17) & ((1 << 4) - 1)) | ((Z[j + 20] & ((1 << 21) - 1)) << 4) | (Z[j + 21] << 25)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 14), (int)((((Z[j + 21] >>> 7) & ((1 << 14) - 1))) | (Z[j + 22] << 14)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 15), (int)(((Z[j + 22] >>> 18) & ((1 << 3) - 1)) | ((Z[j + 23] & ((1 << 21) - 1)) << 3) | (Z[j + 24] << 24)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 16), (int)((((Z[j + 24] >>> 8) & ((1 << 13) - 1))) | (Z[j + 25] << 13)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 17), (int)(((Z[j + 25] >>> 19) & ((1 << 2) - 1)) | ((Z[j + 26] & ((1 << 21) - 1)) << 2) | (Z[j + 27] << 23)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 18), (int)((((Z[j + 27] >>> 9) & ((1 << 12) - 1))) | (Z[j + 28] << 12)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 19), (int)(((Z[j + 28] >>> 20) & ((1 << 1) - 1)) | ((Z[j + 29] & ((1 << 21) - 1)) << 1) | (Z[j + 30] << 22)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 20), (int)((((Z[j + 30] >>> 10) & ((1 << 11) - 1))) | (Z[j + 31] << 11)));

            j += Integer.SIZE;

        }

        System.arraycopy(C, cOffset, signature, signatureOffset + n * d / Byte.SIZE, Polynomial.HASH);
    }

    /********************************************************************************************************************************************************************************************************
     * Description:	Encode Signature for Heuristic qTESLA Security Category-3 (Option for Speed) and Provably-Secure qTESLA Security Category-1
     ********************************************************************************************************************************************************************************************************/
    private static void encodeSignatureIIISpeedIP(byte[] signature, int signatureOffset, byte[] C, int cOffset, long[] Z, int n, int d)
    {

        int j = 0;

        for (int i = 0; i < (n * d / Integer.SIZE); i += d / 2)
        {

            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 0), (int)(((Z[j + 0] & ((1 << 22) - 1))) | (Z[j + 1] << 22)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 1), (int)((((Z[j + 1] >>> 10) & ((1 << 12) - 1))) | (Z[j + 2] << 12)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 2), (int)(((Z[j + 2] >>> 20) & ((1 << 2) - 1)) | ((Z[j + 3] & ((1 << 22) - 1)) << 2) | (Z[j + 4] << 24)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 3), (int)((((Z[j + 4] >>> 8) & ((1 << 14) - 1))) | (Z[j + 5] << 14)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 4), (int)(((Z[j + 5] >>> 18) & ((1 << 4) - 1)) | ((Z[j + 6] & ((1 << 22) - 1)) << 4) | (Z[j + 7] << 26)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 5), (int)((((Z[j + 7] >>> 6) & ((1 << 16) - 1))) | (Z[j + 8] << 16)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 6), (int)(((Z[j + 8] >>> 16) & ((1 << 6) - 1)) | ((Z[j + 9] & ((1 << 22) - 1)) << 6) | (Z[j + 10] << 28)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 7), (int)((((Z[j + 10] >>> 4) & ((1 << 18) - 1))) | (Z[j + 11] << 18)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 8), (int)(((Z[j + 11] >>> 14) & ((1 << 8) - 1)) | ((Z[j + 12] & ((1 << 22) - 1)) << 8) | (Z[j + 13] << 30)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 9), (int)((((Z[j + 13] >>> 2) & ((1 << 20) - 1))) | (Z[j + 14] << 20)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 10), (int)((((Z[j + 14] >>> 12) & ((1 << 10) - 1))) | (Z[j + 15] << 10)));

            j += Integer.SIZE / 2;

        }

        System.arraycopy(C, cOffset, signature, signatureOffset + n * d / Byte.SIZE, Polynomial.HASH);

    }

    /***************************************************************************************************************************************************************
     * Description:	Encode Signature for Provably-Secure qTESLA Security Category-3
     ***************************************************************************************************************************************************************/
    private static void encodeSignature(byte[] signature, int signatureOffset, byte[] C, int cOffset, long[] Z)
    {
        int j = 0;

        for (int i = 0; i < (Parameter.N_III_P * Parameter.D_III_P / Integer.SIZE); i += Parameter.D_III_P / Byte.SIZE)
        {

            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 0), (int)(((Z[j + 0] & ((1 << 24) - 1))) | (Z[j + 1] << 24)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 1), (int)((((Z[j + 1] >> 8) & ((1 << 16) - 1))) | (Z[j + 2] << 16)));
            CommonFunction.store32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 2), (int)((((Z[j + 2] >> 16) & ((1 << 8) - 1))) | (Z[j + 3] << 8)));

            j += Byte.SIZE / 2;

        }

        System.arraycopy(C, cOffset, signature, signatureOffset + Parameter.N_III_P * Parameter.D_III_P / Byte.SIZE, Polynomial.HASH);

    }

    /************************************************************************************************************************
     * Description:	Decode Signature for Heuristic qTESLA Security Category-1 and Category-3 (Option for Size)
     ************************************************************************************************************************/
    private static void decodeSignature(byte[] C, long[] Z, final byte[] signature, int signatureOffset, int n, int d)
    {

        int j = 0;

        for (int i = 0; i < n; i += Integer.SIZE)
        {

            Z[i + 0] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 0)) << 11) >> 11;

            Z[i + 1] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 0)) >>> 21) |
                ((CommonFunction.load32(signature, signatureOffset + 4 * (j + 1)) << 22) >> 11);

            Z[i + 2] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 1)) << 1) >> 11;

            Z[i + 3] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 1)) >>> 31) |
                ((CommonFunction.load32(signature, signatureOffset + 4 * (j + 2)) << 12) >> 11);

            Z[i + 4] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 2)) >>> 20) |
                ((CommonFunction.load32(signature, signatureOffset + 4 * (j + 3)) << 23) >> 11);

            Z[i + 5] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 3)) << 2) >> 11;

            Z[i + 6] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 3)) >>> 30) |
                ((CommonFunction.load32(signature, signatureOffset + 4 * (j + 4)) << 13) >> 11);

            Z[i + 7] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 4)) >>> 19) |
                ((CommonFunction.load32(signature, signatureOffset + 4 * (j + 5)) << 24) >> 11);

            Z[i + 8] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 5)) << 3) >> 11;

            Z[i + 9] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 5)) >>> 29) |
                ((CommonFunction.load32(signature, signatureOffset + 4 * (j + 6)) << 14) >> 11);

            Z[i + 10] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 6)) >>> 18) |
                ((CommonFunction.load32(signature, signatureOffset + 4 * (j + 7)) << 25) >> 11);

            Z[i + 11] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 7)) << 4) >> 11;

            Z[i + 12] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 7)) >>> 28) |
                ((CommonFunction.load32(signature, signatureOffset + 4 * (j + 8)) << 15) >> 11);

            Z[i + 13] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 8)) >>> 17) |
                ((CommonFunction.load32(signature, signatureOffset + 4 * (j + 9)) << 26) >> 11);

            Z[i + 14] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 9)) << 5) >> 11;

            Z[i + 15] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 9)) >>> 27) |
                ((CommonFunction.load32(signature, signatureOffset + 4 * (j + 10)) << 16) >> 11);

            Z[i + 16] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 10)) >>> 16) |
                ((CommonFunction.load32(signature, signatureOffset + 4 * (j + 11)) << 27) >> 11);

            Z[i + 17] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 11)) << 6) >> 11;

            Z[i + 18] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 11)) >>> 26) |
                ((CommonFunction.load32(signature, signatureOffset + 4 * (j + 12)) << 17) >> 11);

            Z[i + 19] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 12)) >>> 15) |
                ((CommonFunction.load32(signature, signatureOffset + 4 * (j + 13)) << 28) >> 11);

            Z[i + 20] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 13)) << 7) >> 11;

            Z[i + 21] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 13)) >>> 25) |
                ((CommonFunction.load32(signature, signatureOffset + 4 * (j + 14)) << 18) >> 11);

            Z[i + 22] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 14)) >>> 14) |
                ((CommonFunction.load32(signature, signatureOffset + 4 * (j + 15)) << 29) >> 11);

            Z[i + 23] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 15)) << 8) >> 11;

            Z[i + 24] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 15)) >>> 24) |
                ((CommonFunction.load32(signature, signatureOffset + 4 * (j + 16)) << 19) >> 11);

            Z[i + 25] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 16)) >>> 13) |
                ((CommonFunction.load32(signature, signatureOffset + 4 * (j + 17)) << 30) >> 11);

            Z[i + 26] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 17)) << 9) >> 11;

            Z[i + 27] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 17)) >>> 23) |
                ((CommonFunction.load32(signature, signatureOffset + 4 * (j + 18)) << 20) >> 11);

            Z[i + 28] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 18)) >>> 12) |
                ((CommonFunction.load32(signature, signatureOffset + 4 * (j + 19)) << 31) >> 11);

            Z[i + 29] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 19)) << 10) >> 11;

            Z[i + 30] = (CommonFunction.load32(signature, signatureOffset + 4 * (j + 19)) >>> 22) |
                ((CommonFunction.load32(signature, signatureOffset + 4 * (j + 20)) << 21) >> 11);

            Z[i + 31] = CommonFunction.load32(signature, signatureOffset + 4 * (j + 20)) >> 11;

            j += d;

        }

        System.arraycopy(signature, signatureOffset + n * d / Byte.SIZE, C, 0, Polynomial.HASH);
    }

    /**********************************************************************************************************************************
     * Description:	Decode Signature for Heuristic qTESLA Security Category-3 (Option for Speed) and
     * 				Provably-Secure qTESLA Security Category-1
     **********************************************************************************************************************************/
    private static void decodeSignatureIIISpeedIP(byte[] C, long[] Z, final byte[] sig, int sOff, int n, int d)
    {

        int j = 0;

        for (int i = 0; i < n; i += Integer.SIZE / 2)
        {

            Z[i + 0] = (CommonFunction.load32(sig, sOff + 4 * (j + 0)) << 10) >> 10;

            Z[i + 1] = (CommonFunction.load32(sig, sOff + 4 * (j + 0)) >>> 22) |
                ((CommonFunction.load32(sig, sOff + 4 * (j + 1)) << 20) >> 10);

            Z[i + 2] = (CommonFunction.load32(sig, sOff + 4 * (j + 1)) >>> 12) |
                ((CommonFunction.load32(sig, sOff + 4 * (j + 2)) << 30) >> 10);

            Z[i + 3] = (CommonFunction.load32(sig, sOff + 4 * (j + 2)) << 8) >> 10;

            Z[i + 4] = (CommonFunction.load32(sig, sOff + 4 * (j + 2)) >>> 24) |
                ((CommonFunction.load32(sig, sOff + 4 * (j + 3)) << 18) >> 10);

            Z[i + 5] = (CommonFunction.load32(sig, sOff + Integer.SIZE / Byte.SIZE * (j + 3)) >>> 14) |
                ((CommonFunction.load32(sig, sOff + Integer.SIZE / Byte.SIZE * (j + 4)) << 28) >> 10);

            Z[i + 6] = (CommonFunction.load32(sig, sOff + Integer.SIZE / Byte.SIZE * (j + 4)) << 6) >> 10;

            Z[i + 7] = (CommonFunction.load32(sig, sOff + Integer.SIZE / Byte.SIZE * (j + 4)) >>> 26) |
                ((CommonFunction.load32(sig, sOff + Integer.SIZE / Byte.SIZE * (j + 5)) << 16) >> 10);

            Z[i + 8] = (CommonFunction.load32(sig, sOff + Integer.SIZE / Byte.SIZE * (j + 5)) >>> 16) |
                ((CommonFunction.load32(sig, sOff + Integer.SIZE / Byte.SIZE * (j + 6)) << 26) >> 10);

            Z[i + 9] = (CommonFunction.load32(sig, sOff + Integer.SIZE / Byte.SIZE * (j + 6)) << 4) >> 10;

            Z[i + 10] = (CommonFunction.load32(sig, sOff + Integer.SIZE / Byte.SIZE * (j + 6)) >>> 28) |
                ((CommonFunction.load32(sig, sOff + Integer.SIZE / Byte.SIZE * (j + 7)) << 14) >> 10);

            Z[i + 11] = (CommonFunction.load32(sig, sOff + Integer.SIZE / Byte.SIZE * (j + 7)) >>> 18) |
                ((CommonFunction.load32(sig, sOff + Integer.SIZE / Byte.SIZE * (j + 8)) << 24) >> 10);

            Z[i + 12] = (CommonFunction.load32(sig, sOff + Integer.SIZE / Byte.SIZE * (j + 8)) << 2) >> 10;

            Z[i + 13] = (CommonFunction.load32(sig, sOff + Integer.SIZE / Byte.SIZE * (j + 8)) >>> 30) |
                ((CommonFunction.load32(sig, sOff + Integer.SIZE / Byte.SIZE * (j + 9)) << 12) >> 10);

            Z[i + 14] = (CommonFunction.load32(sig, sOff + Integer.SIZE / Byte.SIZE * (j + 9)) >>> 20) |
                ((CommonFunction.load32(sig, sOff + Integer.SIZE / Byte.SIZE * (j + 10)) << 22) >> 10);

            Z[i + 15] = CommonFunction.load32(sig, sOff + Integer.SIZE / Byte.SIZE * (j + 10)) >> 10;

            j += d / 2;

        }

        System.arraycopy(sig, sOff + n * d / Byte.SIZE, C, 0, Polynomial.HASH);
    }

    /**********************************************************************************************************************************
     * Description:	Decode Signature for Provably-Secure qTESLA Security Category-3
     **********************************************************************************************************************************/
    private static void decodeSignature(byte[] C, long[] Z, final byte[] signature, int signatureOffset)
    {

        int j = 0;

        for (int i = 0; i < Parameter.N_III_P; i += Byte.SIZE / 2)
        {

            Z[i + 0] = (CommonFunction.load32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 0)) << 8) >> 8;

            Z[i + 1] = ((CommonFunction.load32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 0)) >>> 24) & ((1 << 8) - 1)) |
                ((CommonFunction.load32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 1)) << 16) >> 8);

            Z[i + 2] = ((CommonFunction.load32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 1)) >>> 16) & ((1 << 16) - 1)) |
                ((CommonFunction.load32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 2)) << 24) >> 8);

            Z[i + 3] = CommonFunction.load32(signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 2)) >> 8;

            j += Byte.SIZE / 2 - 1;

        }

        System.arraycopy(signature, signatureOffset + Parameter.N_III_P * Parameter.D_III_P / Byte.SIZE, C, 0, Polynomial.HASH);

    }

    /********************************************************************************************************************************************************************
     * Description:	Hash Function to Generate C' for Heuristic qTESLA Security Category-1 and Category-3 (Option for Size or Speed)
     ********************************************************************************************************************************************************************/
    private static void hashFunction(byte[] output, int outputOffset, long[] V, final byte[] message, int messageOffset, int messageLength, int n, int d, int q)
    {

        long mask;
        long cL;

        byte[] T = new byte[n + messageLength];

        for (int i = 0; i < n; i++)
        {

            mask = (q / 2 - V[i]) >> 63;
            V[i] = ((V[i] - q) & mask) | (V[i] & (~mask));
            cL = V[i] & ((1 << d) - 1);
            mask = ((1 << (d - 1)) - cL) >> 63;
            cL = ((cL - (1 << d)) & mask) | (cL & (~mask));
            T[i] = (byte)((V[i] - cL) >> d);

        }

        System.arraycopy(message, messageOffset, T, n, messageLength);

        if (q == Parameter.Q_I)
        {

            HashUtils.secureHashAlgorithmKECCAK128(output, outputOffset, Polynomial.HASH, T, 0, messageLength + n);

        }

        if (q == Parameter.Q_III_SIZE || q == Parameter.Q_III_SPEED)
        {

            HashUtils.secureHashAlgorithmKECCAK256(output, outputOffset, Polynomial.HASH, T, 0, messageLength + n);

        }

    }

    /*****************************************************************************************************************************************************************************
     * Description:	Hash Function to Generate C' for Provably-Secure qTESLA Security Category-1 and Category-3
     *****************************************************************************************************************************************************************************/
    private static void hashFunction(byte[] output, int outputOffset, long[] V, final byte[] message, int messageOffset, int messageLength, int n, int k, int d, int q)
    {

        int index;
        long mask;
        long cL;
        long temporary;

        byte[] T = new byte[n * k + messageLength];

        for (int j = 0; j < k; j++)
        {

            index = n * j;

            for (int i = 0; i < n; i++)
            {

                temporary = V[index];
                mask = (q / 2 - temporary) >> 63;
                temporary = ((temporary - q) & mask) | (temporary & (~mask));
                cL = temporary & ((1 << d) - 1);
                mask = ((1 << (d - 1)) - cL) >> 63;
                cL = ((cL - (1 << d)) & mask) | (cL & (~mask));
                T[index++] = (byte)((temporary - cL) >> d);

            }

        }

        System.arraycopy(message, messageOffset, T, n * k, messageLength);

        if (q == Parameter.Q_I_P)
        {

            HashUtils.secureHashAlgorithmKECCAK128(output, outputOffset, Polynomial.HASH, T, 0, messageLength + n * k);

        }

        if (q == Parameter.Q_III_P)
        {

            HashUtils.secureHashAlgorithmKECCAK256(output, outputOffset, Polynomial.HASH, T, 0, messageLength + n * k);

        }

    }

    /**************************************************
     * Description:	Computes Absolute Value
     **************************************************/
    private static long absolute(long value)
    {
        return Math.abs(value);
    }

    /*********************************************************************************
     * Description:	Checks Bounds for Signature Vector Z During Signification.
     * 				Leaks the Position of the Coefficient that Fails the Test.
     * 				The Position of the Coefficient is Independent of the Secret Data.
     * 				Does not Leak the Signature of the Coefficients.
     *
     * @param        Z        Signature Vector
     * @param        n        Polynomial Degree
     * @param        b        Interval the Randomness is Chosen in During Signification
     * @param        u        Bound in Checking Secret Polynomial
     *
     * @return false    Valid / Accepted
     * 				true	Invalid / Rejected
     ********************************************************************************/
    private static boolean testRejection(long[] Z, int n, int b, int u)
    {
        for (int i = 0; i < n; i++)
        {
            if (absolute(Z[i]) > (b - u))
            {
                return true;
            }

        }

        return false;
    }

    /**********************************************************************************
     * Description:	Checks Bounds for Signature Vector Z During Signature Verification
     *
     * @param        Z        Signature Vector
     * @param        n        Polynomial Degree
     * @param        b        Interval the Randomness is Chosen in During Signification
     * @param        u        Bound in Checking Secret Polynomial
     *
     * @return false    Valid / Accepted
     * 				true	Invalid / Rejected
     *********************************************************************************/
    private static boolean testZ(long[] Z, int n, int b, int u)
    {
        for (int i = 0; i < n; i++)
        {
            if (absolute(Z[i]) > (b - u))
            {
                return true;
            }
        }

        return false;
    }

    /************************************************************************************************
     * Description:	Checks Bounds for W = V - EC During Signature Verification.
     * 				Leaks the Position of the Coefficient that Fails the Test.
     * 				The Position of the Coefficient is Independent of the Secret Data.
     * 				Does not Leak the Signature of the Coefficients.
     *
     * @param        V            Parameter to be Checked
     * @param        vOffset        Starting Point of V
     * @param        n            Polynomial Degree
     * @param        d            Number of Rounded Bits
     * @param        q            Modulus
     * @param        rejection    Bound in Checking Error Polynomial
     *
     * @return false        Valid / Accepted
     * 				true		Invalid / Rejected
     *************************************************************************************************/
    private static boolean testV(long[] V, int vOffset, int n, int d, int q, int rejection)
    {

        long mask;
        long left;
        long right;
        int rightInteger;
        long test1;
        long test2;

        for (int i = 0; i < n; i++)
        {

            mask = (q / 2 - V[vOffset + i]) >> 63;
            right = ((V[vOffset + i] - q) & mask) | (V[vOffset + i] & (~mask));
            test1 = (~(absolute(right) - (q / 2 - rejection))) >>> 63;

            left = right;
            rightInteger = (int)((right + (1 << (d - 1)) - 1) >> d);
            right = rightInteger;
            right = left - (right << d);
            test2 = (~(absolute(right) - ((1 << (d - 1)) - rejection))) >>> 63;

            /* Two Tests Fail */
            if ((test1 | test2) == 0x1L)
            {

                return true;

            }

        }

        return false;

    }

    /********************************************************************************************************
     * Description:	Checks Whether the Generated Error Polynomial or the Generated Secret Polynomial
     *				Fulfills Certain Properties Needed in Key Generation Algorithm
     *
     * @param        polynomial        Parameter to be Checked
     * @param        offset            Starting Point of the Polynomial to be Checked
     * @param        bound            Threshold of Summation
     * @param        n                Polynomial Degree
     * @param        w                Number of Non-Zero Entries of Output Elements of Encryption
     *
     * @return false            Fulfillment
     * 				true			No Fulfillment
     ********************************************************************************************************/
    private static boolean checkPolynomial(long[] polynomial, int offset, int bound, int n, int w)
    {

        int summation = 0;
        int limit = n;
        short temporary;
        short mask;
        short[] list = new short[n];

        for (int i = 0; i < n; i++)
        {

            list[i] = (short)absolute(polynomial[offset + i]);

        }

        for (int i = 0; i < w; i++)
        {

            for (short j = 0; j < limit - 1; j++)
            {

                mask = (short)((list[j + 1] - list[j]) >> 15);
                temporary = (short)((list[j + 1] & mask) | (list[j] & (~mask)));
                list[j + 1] = (short)((list[j] & mask) | (list[j + 1] & (~mask)));
                list[j] = temporary;

            }

            summation += list[limit - 1];
            limit--;

        }

        if (summation > bound)
        {

            return true;

        }

        return false;

    }

    /*******************************************************************************************************************************************************************************************
     * Description:	Performs Sparse Polynomial Multiplication for A Value Needed During Message Signification for Heuristic qTESLA Security Category-1 and Category-3 (Option for Size or Speed)
     *
     * @param        product                Product of Two Polynomials
     * @param        privateKey            Private Key
     * @param        privateKeyOffset    Starting Point of the Private Key
     * @param        positionList        List of Indices of Non-Zero Elements in C
     * @param        signList            List of Signs of Non-Zero Elements in C
     * @param        n                    Polynomial Degree
     * @param        w                    Number of Non-Zero Entries of Output Elements of Encryption
     *
     * @return none
     ********************************************************************************************************************************************************************************************/
    private static void sparsePolynomialMultiplication16(long[] product, final byte[] privateKey, int privateKeyOffset, final int[] positionList, final short[] signList, int n, int w)
    {

        int position;

        Arrays.fill(product, 0L);

        for (int i = 0; i < w; i++)
        {

            position = positionList[i];

            for (int j = 0; j < position; j++)
            {

                product[j] -= signList[i] * CommonFunction.load16(privateKey, privateKeyOffset + Short.SIZE / Byte.SIZE * (n + j - position));

            }

            for (int j = position; j < n; j++)
            {

                product[j] += signList[i] * CommonFunction.load16(privateKey, privateKeyOffset + Short.SIZE / Byte.SIZE * (j - position));

            }

        }

    }

    /******************************************************************************************************************************************************************************************************
     * Description:	Performs Sparse Polynomial Multiplication for A Value Needed During Message Signification for Provably-Secure qTESLA Security Category-1 and Category-3
     *
     * @param        product                Product of Two Polynomials
     * @param        productOffset        Starting Point of the Product of Two Polynomials
     * @param        privateKey            Private Key
     * @param        privateKeyOffset    Starting Point of the Private Key
     * @param        positionList        List of Indices of Non-Zero Elements in C
     * @param        signList            List of Signs of Non-Zero Elements in C
     * @param        n                    Polynomial Degree
     * @param        w                    Number of Non-Zero Entries of Output Elements of Encryption
     *
     * @return none
     *******************************************************************************************************************************************************************************************************/
    private static void sparsePolynomialMultiplication8(long[] product, int productOffset, final byte[] privateKey, int privateKeyOffset, final int[] positionList, final short[] signList, int n, int w)
    {

        int position;

        Arrays.fill(product, 0L);

        for (int i = 0; i < w; i++)
        {

            position = positionList[i];

            for (int j = 0; j < position; j++)
            {

                product[productOffset + j] -= signList[i] * privateKey[privateKeyOffset + n + j - position];

            }

            for (int j = position; j < n; j++)
            {

                product[productOffset + j] += signList[i] * privateKey[privateKeyOffset + j - position];

            }

        }

    }

    /**************************************************************************************************************************************************************************************************************************************************************************
     * Description:	Performs Sparse Polynomial Multiplication for A Value Needed During Message Signification
     *
     * @param        product                    Product of Two Polynomials
     * @param        productOffset            Starting Point of the Product of Two Polynomials
     * @param        publicKey                Public Key
     * @param        publicKeyOffset            Starting Point of the Public Key
     * @param        positionList            List of Indices of Non-Zero Elements in C
     * @param        signList                List of Signs of Non-Zero Elements in C
     * @param        n                        Polynomial Degree
     * @param        w                        Number of Non-Zero Entries of Output Elements of Encryption
     * @param        q                        Modulus
     * @param        barrettMultiplication
     * @param        barrettDivision
     *
     * @return none
     **************************************************************************************************************************************************************************************************************************************************************************/
    private static void sparsePolynomialMultiplication32(long[] product, int productOffset, final int[] publicKey, int publicKeyOffset, final int[] positionList, final short[] signList, int n, int w, int q, int barrettMultiplication, int barrettDivision)
    {

        int position;

        Arrays.fill(product, 0L);

        for (int i = 0; i < w; i++)
        {

            position = positionList[i];

            for (int j = 0; j < position; j++)
            {

                product[productOffset + j] -= signList[i] * publicKey[publicKeyOffset + n + j - position];

            }

            for (int j = position; j < n; j++)
            {

                product[productOffset + j] += signList[i] * publicKey[publicKeyOffset + j - position];

            }

        }

        if (q == Parameter.Q_I || q == Parameter.Q_III_SIZE || q == Parameter.Q_III_SPEED)
        {

            for (int i = 0; i < n; i++)
            {

                product[productOffset + i] = Polynomial.barrett(product[productOffset + i], q, barrettMultiplication, barrettDivision);

            }

        }

        if (q == Parameter.Q_I_P || q == Parameter.Q_III_P)
        {

            for (int i = 0; i < n; i++)
            {

                product[productOffset + i] = Polynomial.barrettP(product[productOffset + i], q, barrettMultiplication, barrettDivision);

            }

        }

    }

    /************************************************************************************************************************************************************
     * Description:	Generates A Pair of Public Key and Private Key for qTESLA Signature Scheme for Heuristic qTESLA Security Category-1
     *				and Category-3 (Option for Size or Speed)
     *
     * @param        publicKey                            Contains Public Key
     * @param        privateKey                            Contains Private Key
     * @param        secureRandom                        Source of Randomness
     * @param        n                                    Polynomial Degree
     * @param        w                                    Number of Non-Zero Entries of Output Elements of Encryption
     * @param        q                                    Modulus
     * @param        qInverse
     * @param        qLogarithm                            q <= 2 ^ qLogarithm
     * @param        generatorA
     * @param        inverseNumberTheoreticTransform
     * @param        xi
     * @param        zeta
     * @param        errorBound                            Bound in Checking Error Polynomial
     * @param        secretBound                            Bound in Checking Secret Polynomial
     *
     * @return 0                                    Successful Execution
     *
     ************************************************************************************************************************************************************/
    private static int generateKeyPair(

        byte[] publicKey, byte[] privateKey, SecureRandom secureRandom,
        int n, int w, int q, long qInverse, int qLogarithm, int generatorA, int inverseNumberTheoreticTransform, double xi,
        long[] zeta,
        int errorBound, int secretBound)
    {

        /* Initialize Domain Separator for Error Polynomial and Secret Polynomial */
        int nonce = 0;

        byte[] randomness = new byte[Polynomial.RANDOM];

        /* Extend Random Bytes to Seed Generation of Error Polynomial and Secret Polynomial */
        byte[] randomnessExtended = new byte[Polynomial.SEED * 4];

        long[] secretPolynomial = new long[n];
        long[] errorPolynomial = new long[n];
        long[] A = new long[n];
        long[] T = new long[n];

        /* Get randomnessExtended <- seedErrorPolynomial, seedSecretPolynomial, seedA, seedY */
        // this.rng.randomByte (randomness, (short) 0, Polynomial.RANDOM);
        secureRandom.nextBytes(randomness);

        if (q == Parameter.Q_I)
        {

            HashUtils.secureHashAlgorithmKECCAK128(randomnessExtended, 0, Polynomial.SEED * 4, randomness, 0, Polynomial.RANDOM);

        }

        if (q == Parameter.Q_III_SIZE || q == Parameter.Q_III_SPEED)
        {

            HashUtils.secureHashAlgorithmKECCAK256(randomnessExtended, 0, Polynomial.SEED * 4, randomness, 0, Polynomial.RANDOM);

        }

        /*
         * Sample the Error Polynomial Fulfilling the Criteria
         * Choose All Error Polynomial in R with Entries from D_SIGMA
         * Repeat Step at Iteration if the h Largest Entries of Error Polynomial Summation to L_E
         */
        do
        {

            if (q == Parameter.Q_I)
            {

                Sample.polynomialGaussSamplerI(errorPolynomial, 0, randomnessExtended, 0, ++nonce, n, xi, Sample.EXPONENTIAL_DISTRIBUTION_I);

            }

            if (q == Parameter.Q_III_SIZE)
            {

                Sample.polynomialGaussSamplerIII(errorPolynomial, 0, randomnessExtended, 0, ++nonce, n, xi, Sample.EXPONENTIAL_DISTRIBUTION_III_SIZE);

            }

            if (q == Parameter.Q_III_SPEED)
            {

                Sample.polynomialGaussSamplerIII(errorPolynomial, 0, randomnessExtended, 0, ++nonce, n, xi, Sample.EXPONENTIAL_DISTRIBUTION_III_SPEED);

            }


        }
        while (checkPolynomial(errorPolynomial, 0, errorBound, n, w) == true);

        /*
         * Sample the Secret Polynomial Fulfilling the Criteria
         * Choose Secret Polynomial in R with Entries from D_SIGMA
         * Repeat Step if the h Largest Entries of Secret Polynomial Summation to L_S
         */
        do
        {

            if (q == Parameter.Q_I)
            {

                Sample.polynomialGaussSamplerI(secretPolynomial, 0, randomnessExtended, 0, ++nonce, n, xi, Sample.EXPONENTIAL_DISTRIBUTION_I);

            }

            if (q == Parameter.Q_III_SIZE)
            {

                Sample.polynomialGaussSamplerIII(secretPolynomial, 0, randomnessExtended, 0, ++nonce, n, xi, Sample.EXPONENTIAL_DISTRIBUTION_III_SIZE);

            }

            if (q == Parameter.Q_III_SPEED)
            {

                Sample.polynomialGaussSamplerIII(secretPolynomial, 0, randomnessExtended, 0, ++nonce, n, xi, Sample.EXPONENTIAL_DISTRIBUTION_III_SPEED);

            }

        }
        while (checkPolynomial(secretPolynomial, 0, secretBound, n, w) == true);

        /* Generate Uniform Polynomial A */
        Polynomial.polynomialUniform(
            A, randomnessExtended, Polynomial.SEED * 2, n, 1, q, qInverse, qLogarithm, generatorA, inverseNumberTheoreticTransform
        );

        /* Compute the Public Key T = A * secretPolynomial + errorPolynomial */
        Polynomial.polynomialMultiplication(T, 0, A, 0, secretPolynomial, 0, n, q, qInverse, zeta);

        Polynomial.polynomialAddition(T, 0, T, 0, errorPolynomial, 0, n);

        /* Pack Public and Private Keys */
        packPrivateKey(privateKey, secretPolynomial, errorPolynomial, randomnessExtended, Polynomial.SEED * 2, n);

        if (q == Parameter.Q_I)
        {

            encodePublicKey(publicKey, T, randomnessExtended, Polynomial.SEED * 2, n, Parameter.Q_LOGARITHM_I);

        }

        if (q == Parameter.Q_III_SIZE)
        {

            encodePublicKey(publicKey, T, randomnessExtended, Polynomial.SEED * 2, n, Parameter.Q_LOGARITHM_III_SIZE);

        }

        if (q == Parameter.Q_III_SPEED)
        {

            encodePublicKeyIIISpeed(publicKey, T, randomnessExtended, Polynomial.SEED * 2);

        }

        return 0;

    }

    /****************************************************************************************************************************************************************
     * Description:	Generates A Pair of Public Key and Private Key for qTESLA Signature Scheme for
     * 				Heuristic qTESLA Security Category-1
     *
     * @param        publicKey                            Contains Public Key
     * @param        privateKey                            Contains Private Key
     * @param        secureRandom                        Source of Randomness
     *
     * @return 0                                    Successful Execution
     *
     ****************************************************************************************************************************************************************/
    static int generateKeyPairI(byte[] publicKey, byte[] privateKey, SecureRandom secureRandom)
    {

        return generateKeyPair(
            publicKey, privateKey, secureRandom,
            Parameter.N_I, Parameter.W_I, Parameter.Q_I, Parameter.Q_INVERSE_I, Parameter.Q_LOGARITHM_I,
            Parameter.GENERATOR_A_I, Parameter.INVERSE_NUMBER_THEORETIC_TRANSFORM_I,
            Parameter.XI_I,
            PolynomialHeuristic.ZETA_I,
            Parameter.KEY_GENERATOR_BOUND_E_I, Parameter.KEY_GENERATOR_BOUND_S_I
        );

    }

    /****************************************************************************************************************************************************************
     * Description:	Generates A Pair of Public Key and Private Key for qTESLA Signature Scheme for Heuristic qTESLA Security Category-3 (Option for Size)
     *
     * @param        publicKey                            Contains Public Key
     * @param        privateKey                            Contains Private Key
     * @param        secureRandom                        Source of Randomness
     *
     * @return 0                                    Successful Execution
     *
     ****************************************************************************************************************************************************************/
    static int generateKeyPairIIISize(byte[] publicKey, byte[] privateKey, SecureRandom secureRandom)
    {

        return generateKeyPair(
            publicKey, privateKey, secureRandom,
            Parameter.N_III_SIZE, Parameter.W_III_SIZE, Parameter.Q_III_SIZE, Parameter.Q_INVERSE_III_SIZE, Parameter.Q_LOGARITHM_III_SIZE,
            Parameter.GENERATOR_A_III_SIZE, Parameter.INVERSE_NUMBER_THEORETIC_TRANSFORM_III_SIZE,
            Parameter.XI_III_SIZE,
            PolynomialHeuristic.ZETA_III_SIZE,
            Parameter.KEY_GENERATOR_BOUND_E_III_SIZE, Parameter.KEY_GENERATOR_BOUND_S_III_SIZE
        );

    }

    /****************************************************************************************************************************************************************
     * Description:	Generates A Pair of Public Key and Private Key for qTESLA Signature Scheme for Heuristic qTESLA Security Category-3
     * 				(Option for Speed)
     *
     * @param        publicKey                            Contains Public Key
     * @param        privateKey                            Contains Private Key
     * @param        secureRandom                        Source of Randomness
     *
     * @return 0                                    Successful Execution
     *
     ****************************************************************************************************************************************************************/
    static int generateKeyPairIIISpeed(byte[] publicKey, byte[] privateKey, SecureRandom secureRandom)
    {

        return generateKeyPair(
            publicKey, privateKey, secureRandom,
            Parameter.N_III_SPEED, Parameter.W_III_SPEED, Parameter.Q_III_SPEED, Parameter.Q_INVERSE_III_SPEED, Parameter.Q_LOGARITHM_III_SPEED,
            Parameter.GENERATOR_A_III_SPEED, Parameter.INVERSE_NUMBER_THEORETIC_TRANSFORM_III_SPEED,
            Parameter.XI_III_SPEED,
            PolynomialHeuristic.ZETA_III_SPEED,
            Parameter.KEY_GENERATOR_BOUND_E_III_SPEED, Parameter.KEY_GENERATOR_BOUND_S_III_SPEED
        );

    }

    /*******************************************************************************************************************************************************
     * Description:	Generates A Pair of Public Key and Private Key for qTESLA Signature Scheme for Provably-Secure qTESLA Security Category-1
     * 				and Category-3
     *
     * @param        publicKey                            Contains Public Key
     * @param        privateKey                            Contains Private Key
     * @param        secureRandom                        Source of Randomness
     * @param        n                                    Polynomial Degree
     * @param        k                                    Number of Ring-Learning-With-Errors Samples
     * @param        w                                    Number of Non-Zero Entries of Output Elements of Encryption
     * @param        q                                    Modulus
     * @param        qInverse
     * @param        qLogarithm                            q <= 2 ^ qLogarithm
     * @param        generatorA
     * @param        inverseNumberTheoreticTransform
     * @param        xi
     * @param        zeta
     * @param        errorBound                            Bound in Checking Error Polynomial
     * @param        secretBound                            Bound in Checking Secret Polynomial
     *
     * @return 0                                    Successful Execution
     *******************************************************************************************************************************************************/
    private static int generateKeyPair(

        byte[] publicKey, byte[] privateKey, SecureRandom secureRandom,
        int n, int k, int w, int q, long qInverse, int qLogarithm, int generatorA, int inverseNumberTheoreticTransform, double xi,
        long[] zeta,
        int errorBound, int secretBound

    )
    {

        /* Initialize Domain Separator for Error Polynomial and Secret Polynomial */
        int nonce = 0;

        long mask;

        byte[] randomness = new byte[Polynomial.RANDOM];

        /* Extend Random Bytes to Seed Generation of Error Polynomial and Secret Polynomial */
        byte[] randomnessExtended = new byte[Polynomial.SEED * (k + 3)];

        long[] secretPolynomial = new long[n];
        long[] secretPolynomialNumberTheoreticTransform = new long[n];
        long[] errorPolynomial = new long[n * k];
        long[] A = new long[n * k];
        long[] T = new long[n * k];

        /* Get randomnessExtended <- seedErrorPolynomial, seedSecretPolynomial, seedA, seedY */
        // this.rng.randomByte (randomness, (short) 0, Polynomial.RANDOM);
        secureRandom.nextBytes(randomness);

        if (q == Parameter.Q_I_P)
        {

            HashUtils.secureHashAlgorithmKECCAK128(
                randomnessExtended, 0, Polynomial.SEED * (k + 3), randomness, 0, Polynomial.RANDOM
            );

        }

        if (q == Parameter.Q_III_P)
        {

            HashUtils.secureHashAlgorithmKECCAK256(
                randomnessExtended, 0, Polynomial.SEED * (k + 3), randomness, 0, Polynomial.RANDOM
            );

        }

        /*
         * Sample the Error Polynomial Fulfilling the Criteria
         * Choose All Error Polynomial_i in R with Entries from D_SIGMA
         * Repeat Step at Iteration if the h Largest Entries of Error Polynomial_k Summation to L_E
         */
        for (int i = 0; i < k; i++)
        {

            do
            {

                if (q == Parameter.Q_I_P)
                {

                    Sample.polynomialGaussSamplerI(
                        errorPolynomial, n * i, randomnessExtended, Polynomial.SEED * i, ++nonce, n, xi, Sample.EXPONENTIAL_DISTRIBUTION_P
                    );

                }

                if (q == Parameter.Q_III_P)
                {

                    Sample.polynomialGaussSamplerIII(
                        errorPolynomial, n * i, randomnessExtended, Polynomial.SEED * i, ++nonce, n, xi, Sample.EXPONENTIAL_DISTRIBUTION_P
                    );

                }

            }
            while (checkPolynomial(errorPolynomial, n * i, errorBound, n, w) == true);

        }

        /*
         * Sample the Secret Polynomial Fulfilling the Criteria
         * Choose Secret Polynomial in R with Entries from D_SIGMA
         * Repeat Step if the h Largest Entries of Secret Polynomial Summation to L_S
         */
        do
        {

            if (q == Parameter.Q_I_P)
            {

                Sample.polynomialGaussSamplerI(
                    secretPolynomial, 0, randomnessExtended, Polynomial.SEED * k, ++nonce, n, xi, Sample.EXPONENTIAL_DISTRIBUTION_P
                );

            }

            if (q == Parameter.Q_III_P)
            {

                Sample.polynomialGaussSamplerIII(
                    secretPolynomial, 0, randomnessExtended, Polynomial.SEED * k, ++nonce, n, xi, Sample.EXPONENTIAL_DISTRIBUTION_P
                );

            }

        }
        while (checkPolynomial(secretPolynomial, 0, secretBound, n, w) == true);

        /* Generate Uniform Polynomial A */
        Polynomial.polynomialUniform(
            A, randomnessExtended, Polynomial.SEED * (k + 1), n, k, q, qInverse, qLogarithm, generatorA, inverseNumberTheoreticTransform
        );

        Polynomial.polynomialNumberTheoreticTransform(secretPolynomialNumberTheoreticTransform, secretPolynomial, n);

        /* Compute the Public Key T = A * secretPolynomial + errorPolynomial */
        for (int i = 0; i < k; i++)
        {

            Polynomial.polynomialMultiplication(T, n * i, A, n * i, secretPolynomialNumberTheoreticTransform, 0, n, q, qInverse);

            Polynomial.polynomialAddition(T, n * i, T, n * i, errorPolynomial, n * i, n);

            for (int j = 0; j < n; j++)
            {

                mask = (q - T[n * i + j]) >> 63;
                T[n * i + j] -= (q & mask);

            }

        }

        /* Pack Public and Private Keys */
        packPrivateKey(privateKey, secretPolynomial, errorPolynomial, randomnessExtended, Polynomial.SEED * (k + 1), n, k);

        if (q == Parameter.Q_I_P)
        {

            encodePublicKeyIP(publicKey, T, randomnessExtended, Polynomial.SEED * (k + 1));

        }

        if (q == Parameter.Q_III_P)
        {

            encodePublicKeyIIIP(publicKey, T, randomnessExtended, Polynomial.SEED * (k + 1));

        }

        return 0;

    }

    /****************************************************************************************************************************************************************
     * Description:	Generates A Pair of Public Key and Private Key for qTESLA Signature Scheme for Provably-Secure qTESLA Security Category-1
     *
     * @param        publicKey                            Contains Public Key
     * @param        privateKey                            Contains Private Key
     * @param        secureRandom                        Source of Randomness
     *
     * @return 0                                    Successful Execution
     ****************************************************************************************************************************************************************/
    static int generateKeyPairIP(byte[] publicKey, byte[] privateKey, SecureRandom secureRandom)
    {

        return generateKeyPair(
            publicKey, privateKey, secureRandom,
            Parameter.N_I_P, Parameter.K_I_P, Parameter.W_I_P, Parameter.Q_I_P, Parameter.Q_INVERSE_I_P, Parameter.Q_LOGARITHM_I_P,
            Parameter.GENERATOR_A_I_P, Parameter.INVERSE_NUMBER_THEORETIC_TRANSFORM_I_P,
            Parameter.XI_I_P,
            PolynomialProvablySecure.ZETA_I_P,
            Parameter.KEY_GENERATOR_BOUND_E_I_P, Parameter.KEY_GENERATOR_BOUND_S_I_P
        );

    }

    /****************************************************************************************************************************************************************
     * Description:	Generates A Pair of Public Key and Private Key for qTESLA Signature Scheme for Provably-Secure qTESLA Security Category-3
     *
     * @param        publicKey                            Contains Public Key
     * @param        privateKey                            Contains Private Key
     * @param        secureRandom                        Source of Randomness
     *
     * @return 0                                    Successful Execution
     ****************************************************************************************************************************************************************/
    static int generateKeyPairIIIP(byte[] publicKey, byte[] privateKey, SecureRandom secureRandom)
    {

        return generateKeyPair(
            publicKey, privateKey, secureRandom,
            Parameter.N_III_P, Parameter.K_III_P, Parameter.W_III_P, Parameter.Q_III_P, Parameter.Q_INVERSE_III_P, Parameter.Q_LOGARITHM_III_P,
            Parameter.GENERATOR_A_III_P, Parameter.INVERSE_NUMBER_THEORETIC_TRANSFORM_III_P,
            Parameter.XI_III_P,
            PolynomialProvablySecure.ZETA_III_P,
            Parameter.KEY_GENERATOR_BOUND_E_III_P, Parameter.KEY_GENERATOR_BOUND_S_III_P
        );

    }

    /******************************************************************************************************************************************************
     * Description:	Generates A Signature for A Given Message According to the Ring-TESLA Signature Scheme for Heuristic qTESLA Security Category-1 and
     * 				Category-3 (Option for Size or Speed)
     *
     * @param        message                                Message to be Signed
     * @param        messageOffset                        Starting Point of the Message to be Signed
     * @param        messageLength                        Length of the Message to be Signed
     * @param        signature                            Output Package Containing Signature
     * @param        privateKey                            Private Key
     * @param        secureRandom                        Source of Randomness
     * @param        n                                    Polynomial Degree
     * @param        w                                    Number of Non-Zero Entries of Output Elements of Encryption
     * @param        q                                    Modulus
     * @param        qInverse
     * @param        qLogarithm                            q <= 2 ^ qLogarithm
     * @param        b                                    Determines the Interval the Randomness is Chosen in During Signing
     * @param        bBit                                b = (2 ^ bBit) - 1
     * @param        d                                    Number of Rounded Bits
     * @param        u                                    Bound in Checking Secret Polynomial
     * @param        rejection                            Bound in Checking Error Polynomial
     * @param        generatorA
     * @param        inverseNumberTheoreticTransform
     * @param        privateKeySize                        Size of the Private Key
     * @param        barrettMultiplication
     * @param        barrettDivision
     * @param        zeta
     *
     * @return 0                                    Successful Execution
     ******************************************************************************************************************************************************/
    private static int signing(
        byte[] signature,
        final byte[] message, int messageOffset, int messageLength,
        final byte[] privateKey, SecureRandom secureRandom,
        int n, int w, int q, long qInverse, int qLogarithm, int b, int bBit, int d, int u, int rejection,
        int generatorA, int inverseNumberTheoreticTransform, int privateKeySize,
        int barrettMultiplication, int barrettDivision,
        long[] zeta)
    {
        byte[] C = new byte[Polynomial.HASH];
        byte[] randomness = new byte[Polynomial.SEED];
        byte[] randomnessInput = new byte[messageLength + Polynomial.RANDOM + Polynomial.SEED];
        byte[] temporaryRandomnessInput = new byte[Polynomial.RANDOM];
        int[] positionList = new int[w];
        short[] signList = new short[w];

        long[] A = new long[n];
        long[] V = new long[n];
        long[] Y = new long[n];
        long[] Z = new long[n];
        long[] SC = new long[n];
        long[] EC = new long[n];

        /* Domain Separator for Sampling Y */
        int nonce = 0;

        secureRandom.nextBytes(temporaryRandomnessInput);

        System.arraycopy(temporaryRandomnessInput, 0, randomnessInput, Polynomial.RANDOM, Polynomial.RANDOM);
        System.arraycopy(privateKey, privateKeySize - Polynomial.SEED, randomnessInput, 0, Polynomial.SEED);
        System.arraycopy(message, messageOffset, randomnessInput, Polynomial.RANDOM + Polynomial.SEED, messageLength);

        if (q == Parameter.Q_I)
        {
            HashUtils.secureHashAlgorithmKECCAK128(
                randomness, 0, Polynomial.SEED, randomnessInput, 0, messageLength + Polynomial.RANDOM + Polynomial.SEED
            );
        }
        else
        {
            HashUtils.secureHashAlgorithmKECCAK256(
                randomness, 0, Polynomial.SEED, randomnessInput, 0, messageLength + Polynomial.RANDOM + Polynomial.SEED
            );
        }

        Polynomial.polynomialUniform(
            A, privateKey, privateKeySize - 2 * Polynomial.SEED, n, 1, q, qInverse, qLogarithm, generatorA, inverseNumberTheoreticTransform
        );

        /* Loop Due to Possible Rejection */
        while (true)
        {

            /* Sample Y Uniformly Random from -B to B */
            Sample.sampleY(Y, randomness, 0, ++nonce, n, q, b, bBit);


            /* V = A * Y Modulo Q */
            Polynomial.polynomialMultiplication(V, 0, A, 0, Y, 0, n, q, qInverse, zeta);

            hashFunction(C, 0, V, message, messageOffset, messageLength, n, d, q);

            /* Generate C = EncodeC (C') Where C' is the Hashing of V Together with Message */
            Sample.encodeC(positionList, signList, C, 0, n, w);

            sparsePolynomialMultiplication16(SC, privateKey, 0, positionList, signList, n, w);

            /* Z = Y + EC Modulo Q */
            Polynomial.polynomialAddition(Z, 0, Y, 0, SC, 0, n);

            /* Rejection Sampling */
            if (testRejection(Z, n, b, u) == true)
            {

                continue;

            }

            sparsePolynomialMultiplication16(EC, privateKey, n * Short.SIZE / Byte.SIZE, positionList, signList, n, w);

            /* V = V - EC modulo Q */
            Polynomial.polynomialSubtraction(V, 0, V, 0, EC, 0, n, q, barrettMultiplication, barrettDivision);

            if (testV(V, 0, n, d, q, rejection) == true)
            {
                continue;
            }

            switch (q)
            {
            case Parameter.Q_I:
                encodeSignature(signature, 0, C, 0, Z, n, d);
                break;
            case Parameter.Q_III_SIZE:
                encodeSignature(signature, 0, C, 0, Z, n, d);
                break;
            case Parameter.Q_III_SPEED:
                encodeSignatureIIISpeedIP(signature, 0, C, 0, Z, n, d);
                break;
            default:
                throw new IllegalStateException("unknown q: " + q);
            }

            return 0;

        }

    }

    /*****************************************************************************************************************************************************
     * Description:	Generates A Signature for A Given Message According to the Ring-TESLA Signature Scheme for Heuristic qTESLA Security Category-1
     *
     * @param        message                                Message to be Signed
     * @param        messageOffset                        Starting Point of the Message to be Signed
     * @param        messageLength                        Length of the Message to be Signed
     * @param        signature                            Output Package Containing Signature
     * @param        privateKey                            Private Key
     * @param        secureRandom                        Source of Randomness
     *
     * @return 0                                    Successful Execution
     *****************************************************************************************************************************************************/
    static int signingI(

        byte[] signature,
        final byte[] message, int messageOffset, int messageLength,
        final byte[] privateKey, SecureRandom secureRandom

    )
    {

        return signing(

            signature,
            message, messageOffset, messageLength,
            privateKey, secureRandom,
            Parameter.N_I, Parameter.W_I, Parameter.Q_I, Parameter.Q_INVERSE_I, Parameter.Q_LOGARITHM_I,
            Parameter.B_I, Parameter.B_BIT_I, Parameter.D_I, Parameter.U_I, Parameter.REJECTION_I,
            Parameter.GENERATOR_A_I, Parameter.INVERSE_NUMBER_THEORETIC_TRANSFORM_I, Polynomial.PRIVATE_KEY_I,
            Parameter.BARRETT_MULTIPLICATION_I, Parameter.BARRETT_DIVISION_I,
            PolynomialHeuristic.ZETA_I

        );

    }

    /*****************************************************************************************************************************************************
     * Description:	Generates A Signature for A Given Message According to the Ring-TESLA Signature Scheme for Heuristic qTESLA Security Category-3
     * 				(Option for Size)
     *
     * @param        message                                Message to be Signed
     * @param        messageOffset                        Starting Point of the Message to be Signed
     * @param        messageLength                        Length of the Message to be Signed
     * @param        signature                            Output Package Containing Signature
     * @param        privateKey                            Private Key
     * @param        secureRandom                        Source of Randomness
     *
     * @return 0                                    Successful Execution
     *****************************************************************************************************************************************************/
    static int signingIIISize(

        byte[] signature,
        final byte[] message, int messageOffset, int messageLength,
        final byte[] privateKey, SecureRandom secureRandom

    )
    {

        return signing(

            signature,
            message, messageOffset, messageLength,
            privateKey, secureRandom,
            Parameter.N_III_SIZE, Parameter.W_III_SIZE, Parameter.Q_III_SIZE, Parameter.Q_INVERSE_III_SIZE, Parameter.Q_LOGARITHM_III_SIZE,
            Parameter.B_III_SIZE, Parameter.B_BIT_III_SIZE, Parameter.D_III_SIZE, Parameter.U_III_SIZE, Parameter.REJECTION_III_SIZE,
            Parameter.GENERATOR_A_III_SIZE, Parameter.INVERSE_NUMBER_THEORETIC_TRANSFORM_III_SIZE, Polynomial.PRIVATE_KEY_III_SIZE,
            Parameter.BARRETT_MULTIPLICATION_III_SIZE, Parameter.BARRETT_DIVISION_III_SIZE,
            PolynomialHeuristic.ZETA_III_SIZE

        );

    }

    /****************************************************************************************************************************************************
     * Description:	Generates A Signature for A Given Message According to the Ring-TESLA Signature Scheme for Heuristic qTESLA Security Category-3
     *				(Option for Speed)
     *
     * @param        message                                Message to be Signed
     * @param        messageOffset                        Starting Point of the Message to be Signed
     * @param        messageLength                        Length of the Message to be Signed
     * @param        signature                            Output Package Containing Signature
     * @param        privateKey                            Private Key
     * @param        secureRandom                        Source of Randomness
     *
     * @return 0                                    Successful Execution
     ****************************************************************************************************************************************************/
    static int signingIIISpeed(

        byte[] signature,
        final byte[] message, int messageOffset, int messageLength,
        final byte[] privateKey, SecureRandom secureRandom

    )
    {

        return signing(

            signature,
            message, messageOffset, messageLength,
            privateKey, secureRandom,
            Parameter.N_III_SPEED, Parameter.W_III_SPEED, Parameter.Q_III_SPEED, Parameter.Q_INVERSE_III_SPEED, Parameter.Q_LOGARITHM_III_SPEED,
            Parameter.B_III_SPEED, Parameter.B_BIT_III_SPEED, Parameter.D_III_SPEED, Parameter.U_III_SPEED, Parameter.REJECTION_III_SPEED,
            Parameter.GENERATOR_A_III_SPEED, Parameter.INVERSE_NUMBER_THEORETIC_TRANSFORM_III_SPEED, Polynomial.PRIVATE_KEY_III_SPEED,
            Parameter.BARRETT_MULTIPLICATION_III_SPEED, Parameter.BARRETT_DIVISION_III_SPEED,
            PolynomialHeuristic.ZETA_III_SPEED

        );

    }

    /*****************************************************************************************************************************************************
     * Description:	Generates A Signature for A Given Message According to the Ring-TESLA Signature Scheme for Provably-Secure qTESLA Security Category-1
     *				and Category-3
     *
     * @param        message                                Message to be Signed
     * @param        messageOffset                        Starting Point of the Message to be Signed
     * @param        messageLength                        Length of the Message to be Signed
     * @param        signature                            Output Package Containing Signature
     * @param        privateKey                            Private Key
     * @param        secureRandom                        Source of Randomness
     * @param        n                                    Polynomial Degree
     * @param        k                                    Number of Ring-Learning-With-Errors Samples
     * @param        w                                    Number of Non-Zero Entries of Output Elements of Encryption
     * @param        q                                    Modulus
     * @param        qInverse
     * @param        qLogarithm                            q <= 2 ^ qLogarithm
     * @param        b                                    Determines the Interval the Randomness is Chosen in During Signing
     * @param        bBit                                b = (2 ^ bBit) - 1
     * @param        d                                    Number of Rounded Bits
     * @param        u                                    Bound in Checking Secret Polynomial
     * @param        rejection                            Bound in Checking Error Polynomial
     * @param        generatorA
     * @param        inverseNumberTheoreticTransform
     * @param        privateKeySize                        Size of the Private Key
     * @param        barrettMultiplication
     * @param        barrettDivision
     *
     * @return 0                                    Successful Execution
     *****************************************************************************************************************************************************/
    private static int signing(

        byte[] signature,
        final byte[] message, int messageOffset, int messageLength,
        final byte[] privateKey, SecureRandom secureRandom,
        int n, int k, int w, int q, long qInverse, int qLogarithm, int b, int bBit, int d, int u, int rejection,
        int generatorA, int inverseNumberTheoreticTransform, int privateKeySize,
        int barrettMultiplication, int barrettDivision

    )
    {

        byte[] C = new byte[Polynomial.HASH];
        byte[] randomness = new byte[Polynomial.SEED];
        byte[] randomnessInput = new byte[messageLength + Polynomial.RANDOM + Polynomial.SEED];
        byte[] temporaryRandomnessInput = new byte[Polynomial.RANDOM];
        int[] positionList = new int[w];
        short[] signList = new short[w];

        long[] A = new long[n * k];
        long[] V = new long[n * k];
        long[] Y = new long[n];
        long[] numberTheoreticTransformY = new long[n];
        long[] Z = new long[n];
        long[] SC = new long[n];
        long[] EC = new long[n * k];

        boolean response = false;

        /* Domain Separator for Sampling Y */
        int nonce = 0;

        secureRandom.nextBytes(temporaryRandomnessInput);
        System.arraycopy(temporaryRandomnessInput, 0, randomnessInput, Polynomial.RANDOM, Polynomial.RANDOM);
        System.arraycopy(privateKey, privateKeySize - Polynomial.SEED, randomnessInput, 0, Polynomial.SEED);
        System.arraycopy(message, messageOffset, randomnessInput, Polynomial.RANDOM + Polynomial.SEED, messageLength);

        if (q == Parameter.Q_I_P)
        {

            HashUtils.secureHashAlgorithmKECCAK128(
                randomness, 0, Polynomial.SEED, randomnessInput, 0, messageLength + Polynomial.RANDOM + Polynomial.SEED
            );

        }
        else
        {

            HashUtils.secureHashAlgorithmKECCAK256(
                randomness, 0, Polynomial.SEED, randomnessInput, 0, messageLength + Polynomial.RANDOM + Polynomial.SEED
            );

        }

        Polynomial.polynomialUniform(
            A, privateKey, privateKeySize - 2 * Polynomial.SEED, n, k, q, qInverse, qLogarithm, generatorA, inverseNumberTheoreticTransform
        );

        /* Loop Due to Possible Rejection */
        while (true)
        {
            /* Sample Y Uniformly Random from -B to B */
            Sample.sampleY(Y, randomness, 0, ++nonce, n, q, b, bBit);

            Polynomial.polynomialNumberTheoreticTransform(numberTheoreticTransformY, Y, n);

            /* V_i = A_i * Y Modulo Q for All i */
            for (short i = 0; i < k; i++)
            {
                Polynomial.polynomialMultiplication(V, n * i, A, n * i, numberTheoreticTransformY, 0, n, q, qInverse);
            }

            hashFunction(C, 0, V, message, messageOffset, messageLength, n, k, d, q);

            /* Generate C = EncodeC (C') Where C' is the Hashing of V Together with Message */
            Sample.encodeC(positionList, signList, C, 0, n, w);

            sparsePolynomialMultiplication8(SC, 0, privateKey, 0, positionList, signList, n, w);

            /* Z = Y + EC modulo Q */
            Polynomial.polynomialAddition(Z, 0, Y, 0, SC, 0, n);

            /* Rejection Sampling */
            if (testRejection(Z, n, b, u) == true)
            {

                continue;

            }

            for (short i = 0; i < k; i++)
            {

                sparsePolynomialMultiplication8(EC, n * i, privateKey, n * (i + 1), positionList, signList, n, w);

                /* V_i = V_i - EC_i Modulo Q for All k */
                Polynomial.polynomialSubtractionP(V, n * i, V, n * i, EC, n * i, n, q, barrettMultiplication, barrettDivision);

                response = testV(V, n * i, n, d, q, rejection);

                if (response == true)
                {

                    break;

                }

            }

            if (response == true)
            {

                continue;

            }

            if (q == Parameter.Q_I_P)
            {
                /* Pack Signature */
                encodeSignatureIIISpeedIP(signature, 0, C, 0, Z, n, d);

            }
            else
            {
                /* Pack Signature */
                encodeSignature(signature, 0, C, 0, Z);
            }

            return 0;

        }

    }

    /*****************************************************************************************************************************************************
     * Description:	Generates A Signature for A Given Message According to the Ring-TESLA Signature Scheme for Provably-Secure qTESLA Security Category-1
     *
     * @param        message                                Message to be Signed
     * @param        messageOffset                        Starting Point of the Message to be Signed
     * @param        messageLength                        Length of the Message to be Signed
     * @param        signature                            Output Package Containing Signature
     * @param        privateKey                            Private Key
     * @param        secureRandom                        Source of Randomness
     *
     * @return 0                                    Successful Execution
     *****************************************************************************************************************************************************/
    static int signingPI(
        byte[] signature,
        final byte[] message, int messageOffset, int messageLength,
        final byte[] privateKey, SecureRandom secureRandom
    )
    {

        return signing(

            signature, 
            message, messageOffset, messageLength,
            privateKey, secureRandom,
            Parameter.N_I_P, Parameter.K_I_P, Parameter.W_I_P, Parameter.Q_I_P, Parameter.Q_INVERSE_I_P, Parameter.Q_LOGARITHM_I_P,
            Parameter.B_I_P, Parameter.B_BIT_I_P, Parameter.D_I_P, Parameter.U_I_P, Parameter.REJECTION_I_P,
            Parameter.GENERATOR_A_I_P, Parameter.INVERSE_NUMBER_THEORETIC_TRANSFORM_I_P, Polynomial.PRIVATE_KEY_I_P,
            Parameter.BARRETT_MULTIPLICATION_I_P, Parameter.BARRETT_DIVISION_I_P

        );

    }

    /**********************************************************************************************************************************************
     * Description:	Generates A Signature for A Given Message According to the Ring-TESLA Signature Scheme for Provably-Secure
     * 				qTESLA Security Category-3
     *
     * @param        message                                Message to be Signed
     * @param        messageOffset                        Starting Point of the Message to be Signed
     * @param        messageLength                        Length of the Message to be Signed
     * @param        signature                            Output Package Containing Signature
     * @param        privateKey                            Private Key
     * @param        secureRandom                        Source of Randomness
     *
     * @return 0                                    Successful Execution
     **********************************************************************************************************************************************/
    static int signingPIII(
        byte[] signature,
        final byte[] message, int messageOffset, int messageLength,
        final byte[] privateKey, SecureRandom secureRandom
    )
    {

        return signing(

            signature, 
            message, messageOffset, messageLength,
            privateKey, secureRandom,
            Parameter.N_III_P, Parameter.K_III_P, Parameter.W_III_P, Parameter.Q_III_P, Parameter.Q_INVERSE_III_P, Parameter.Q_LOGARITHM_III_P,
            Parameter.B_III_P, Parameter.B_BIT_III_P, Parameter.D_III_P, Parameter.U_III_P, Parameter.REJECTION_III_P,
            Parameter.GENERATOR_A_III_P, Parameter.INVERSE_NUMBER_THEORETIC_TRANSFORM_III_P, Polynomial.PRIVATE_KEY_III_P,
            Parameter.BARRETT_MULTIPLICATION_III_P, Parameter.BARRETT_DIVISION_III_P

        );

    }

    /*********************************************************************************************************************************
     * Description:	Extracts the Original Message and Checks Whether the Generated Signature is Valid for A Given Signature Package
     * 				for Heuristic qTESLA Security Category-1 and Category-3 (Option for Size of Speed)
     *
     * @param        signature                            Given Signature Package
     * @param        signatureOffset                        Starting Point of the Given Signature Package
     * @param        signatureLength                        Length of the Given Signature Package
     * @param        message                                Original (Signed) Message
     * @param        publicKey                            Public Key
     * @param        n                                    Polynomial Degree
     * @param        w                                    Number of Non-Zero Entries of Output Elements of Encryption
     * @param        q                                    Modulus
     * @param        qInverse
     * @param        qLogarithm                            q <= 2 ^ qLogarithm
     * @param        b                                    Determines the Interval the Randomness is Chosen in During Signing
     * @param        d                                    Number of Rounded Bits
     * @param        u                                    Bound in Checking Secret Polynomial
     * @param        signatureSize                        Size of the Given Signature Package
     * @param        generatorA
     * @param        inverseNumberTheoreticTransform
     * @param        barrettMultiplication
     * @param        barrettDivision
     * @param        zeta
     *
     * @return 0                                    Valid Signature
     * 				< 0									Invalid Signature
     *********************************************************************************************************************************/
    private static int verifying(

        byte[] message,
        final byte[] signature, int signatureOffset, int signatureLength,
        final byte[] publicKey,
        int n, int w, int q, long qInverse, int qLogarithm, int b, int d, int u, int signatureSize,
        int generatorA, int inverseNumberTheoreticTransform,
        int barrettMultiplication, int barrettDivision,
        long[] zeta

    )
    {

        byte[] C = new byte[Polynomial.HASH];
        byte[] cSignature = new byte[Polynomial.HASH];
        byte[] seed = new byte[Polynomial.SEED];
        int[] newPublicKey = new int[n];

        int[] positionList = new int[w];
        short[] signList = new short[w];

        long[] W = new long[n];
        long[] Z = new long[n];
        long[] TC = new long[n];
        long[] A = new long[n];

        if (signatureLength < signatureSize)
        {

            return -1;

        }

        if (q == Parameter.Q_I || q == Parameter.Q_III_SIZE)
        {
            decodeSignature(C, Z, signature, signatureOffset, n, d);
        }

        if (q == Parameter.Q_III_SPEED)
        {
            decodeSignatureIIISpeedIP(C, Z, signature, signatureOffset, n, d);
        }

        /* Check Norm of Z */
        if (testZ(Z, n, b, u) == true)
        {

            return -2;

        }

        if (q == Parameter.Q_I || q == Parameter.Q_III_SIZE)
        {

            decodePublicKey(newPublicKey, seed, 0, publicKey, n, qLogarithm);

        }

        if (q == Parameter.Q_III_SPEED)
        {
            decodePublicKeyIIISpeed(newPublicKey, seed, 0, publicKey);
        }

        /* Generate A Polynomial */
        Polynomial.polynomialUniform(A, seed, 0, n, 1, q, qInverse, qLogarithm, generatorA, inverseNumberTheoreticTransform);

        Sample.encodeC(positionList, signList, C, 0, n, w);

        /* W = A * Z - TC */
        Polynomial.polynomialMultiplication(W, 0, A, 0, Z, 0, n, q, qInverse, zeta);

        sparsePolynomialMultiplication32(TC, 0, newPublicKey, 0, positionList, signList, n, w, q, barrettMultiplication, barrettDivision);

        Polynomial.polynomialSubtraction(W, 0, W, 0, TC, 0, n, q, barrettMultiplication, barrettDivision);

        /* Obtain the Hash Symbol */
        hashFunction(cSignature, 0, W, message, 0, message.length, n, d, q);
        /* Check if Same With One from Signature */
        if (CommonFunction.memoryEqual(C, 0, cSignature, 0, Polynomial.HASH) == false)
        {
            return -3;
        }

        return 0;

    }

    /*******************************************************************************************************
     * Description:	Extracts the Original Message and Checks Whether the Generated Signature is Valid for
     * 				A Given Signature Package for Heuristic qTESLA Security Category-1
     *
     * @param        signature                            Given Signature Package
     * @param        signatureOffset                        Starting Point of the Given Signature Package
     * @param        signatureLength                        Length of the Given Signature Package
     * @param        message                                Original (Signed) Message
     * @param        publicKey                            Public Key
     *
     * @return 0                                    Valid Signature
     * 				< 0									Invalid Signature
     *******************************************************************************************************/
    static int verifyingI(

        byte[] message,
        final byte[] signature, int signatureOffset, int signatureLength,
        final byte[] publicKey

    )
    {

        return verifying(

            message,
            signature, signatureOffset, signatureLength,
            publicKey,
            Parameter.N_I, Parameter.W_I, Parameter.Q_I, Parameter.Q_INVERSE_I, Parameter.Q_LOGARITHM_I,
            Parameter.B_I, Parameter.D_I, Parameter.U_I, Polynomial.SIGNATURE_I,
            Parameter.GENERATOR_A_I, Parameter.INVERSE_NUMBER_THEORETIC_TRANSFORM_I,
            Parameter.BARRETT_MULTIPLICATION_I, Parameter.BARRETT_DIVISION_I,
            PolynomialHeuristic.ZETA_I

        );

    }

    /******************************************************************************************************
     * Description:	Extracts the Original Message and Checks Whether the Generated Signature is Valid for
     *				A Given Signature Package for Heuristic qTESLA Security Category-3 (Option for Size)
     *
     * @param        signature                            Given Signature Package
     * @param        signatureOffset                        Starting Point of the Given Signature Package
     * @param        signatureLength                        Length of the Given Signature Package
     * @param        message                                Original (Signed) Message
     * @param        publicKey                            Public Key
     *
     * @return 0                                    Valid Signature
     * 				< 0									Invalid Signature
     ******************************************************************************************************/
    static int verifyingIIISize(

        byte[] message,
        final byte[] signature, int signatureOffset, int signatureLength,
        final byte[] publicKey

    )
    {

        return verifying(

            message,
            signature, signatureOffset, signatureLength,
            publicKey,
            Parameter.N_III_SIZE, Parameter.W_III_SIZE,
            Parameter.Q_III_SIZE, Parameter.Q_INVERSE_III_SIZE, Parameter.Q_LOGARITHM_III_SIZE,
            Parameter.B_III_SIZE, Parameter.D_III_SIZE, Parameter.U_III_SIZE, Polynomial.SIGNATURE_III_SIZE,
            Parameter.GENERATOR_A_III_SIZE, Parameter.INVERSE_NUMBER_THEORETIC_TRANSFORM_III_SIZE,
            Parameter.BARRETT_MULTIPLICATION_III_SIZE, Parameter.BARRETT_DIVISION_III_SIZE,
            PolynomialHeuristic.ZETA_III_SIZE

        );

    }

    /**********************************************************************************************************
     * Description:	Extracts the Original Message and Checks Whether the Generated Signature is Valid for
     * 				A Given Signature Package for Heuristic qTESLA Security Category-3 (Option for Speed)
     *
     * @param        signature                            Given Signature Package
     * @param        signatureOffset                        Starting Point of the Given Signature Package
     * @param        signatureLength                        Length of the Given Signature Package
     * @param        message                                Original (Signed) Message
     * @param        publicKey                            Public Key
     *
     * @return 0                                    Valid Signature
     * 				< 0									Invalid Signature
     **********************************************************************************************************/
    static int verifyingIIISpeed(

        byte[] message,
        final byte[] signature, int signatureOffset, int signatureLength,
        final byte[] publicKey

    )
    {

        return verifying(

            message,
            signature, signatureOffset, signatureLength,
            publicKey,
            Parameter.N_III_SPEED, Parameter.W_III_SPEED,
            Parameter.Q_III_SPEED, Parameter.Q_INVERSE_III_SPEED, Parameter.Q_LOGARITHM_III_SPEED,
            Parameter.B_III_SPEED, Parameter.D_III_SPEED, Parameter.U_III_SPEED, Polynomial.SIGNATURE_III_SPEED,
            Parameter.GENERATOR_A_III_SPEED, Parameter.INVERSE_NUMBER_THEORETIC_TRANSFORM_III_SPEED,
            Parameter.BARRETT_MULTIPLICATION_III_SPEED, Parameter.BARRETT_DIVISION_III_SPEED,
            PolynomialHeuristic.ZETA_III_SPEED

        );

    }

    /******************************************************************************************************************************
     * Description:	Extracts the Original Message and Checks Whether the Generated Signature is Valid for A Given Signature Package
     * 				for Provably-Secure qTESLA Security Category-1 and Category-3
     *
     * @param        signature                            Given Signature Package
     * @param        signatureOffset                        Starting Point of the Given Signature Package
     * @param        signatureLength                        Length of the Given Signature Package
     * @param        message                                Original (Signed) Message
     * @param        publicKey                            Public Key
     * @param        n                                    Polynomial Degree
     * @param        k                                    Number of Ring-Learning-With-Errors Samples
     * @param        w                                    Number of Non-Zero Entries of Output Elements of Encryption
     * @param        q                                    Modulus
     * @param        qInverse
     * @param        qLogarithm                            q <= 2 ^ qLogarithm
     * @param        b                                    Determines the Interval the Randomness is Chosen in During Signing
     * @param        d                                    Number of Rounded Bits
     * @param        u                                    Bound in Checking Secret Polynomial
     * @param        generatorA
     * @param        inverseNumberTheoreticTransform
     * @param        barrettMultiplication
     * @param        barrettDivision
     * @param        zeta
     *
     * @return 0                                    Valid Signature
     * 				< 0									Invalid Signature
     ********************************************************************************************************************************/
    private static int verifying(

        byte[] message,
        final byte[] signature, int signatureOffset, int signatureLength,
        final byte[] publicKey,
        int n, int k, int w, int q, long qInverse, int qLogarithm, int b, int d, int u, int signatureSize,
        int generatorA, int inverseNumberTheoreticTransform,
        int barrettMultiplication, int barrettDivision,
        long[] zeta

    )
    {

        byte[] C = new byte[Polynomial.HASH];
        byte[] cSignature = new byte[Polynomial.HASH];
        byte[] seed = new byte[Polynomial.SEED];
        int[] newPublicKey = new int[n * k];

        int[] positionList = new int[w];
        short[] signList = new short[w];

        long[] W = new long[n * k];
        long[] Z = new long[n];
        long[] numberTheoreticTransformZ = new long[n];
        long[] TC = new long[n * k];
        long[] A = new long[n * k];

        if (signatureLength < signatureSize)
        {
            return -1;
        }

        if (q == Parameter.Q_I_P)
        {
            decodeSignatureIIISpeedIP(C, Z, signature, signatureOffset, n, d);
        }

        if (q == Parameter.Q_III_P)
        {
            decodeSignature(C, Z, signature, signatureOffset);
        }

        /* Check Norm of Z */
        if (testZ(Z, n, b, u) == true)
        {
            return -2;
        }

        if (q == Parameter.Q_I_P)
        {
            decodePublicKeyIP(newPublicKey, seed, 0, publicKey);
        }

        if (q == Parameter.Q_III_P)
        {
            decodePublicKeyIIIP(newPublicKey, seed, 0, publicKey);
        }

        /* Generate A Polynomial */
        Polynomial.polynomialUniform(A, seed, 0, n, k, q, qInverse, qLogarithm, generatorA, inverseNumberTheoreticTransform);

        Sample.encodeC(positionList, signList, C, 0, n, w);

        Polynomial.polynomialNumberTheoreticTransform(numberTheoreticTransformZ, Z, n);

        /* W_i = A_i * Z_i - TC_i for All i */
        for (short i = 0; i < k; i++)
        {
            Polynomial.polynomialMultiplication(W, n * i, A, n * i, numberTheoreticTransformZ, 0, n, q, qInverse);

            sparsePolynomialMultiplication32(
                TC, n * i, newPublicKey, n * i, positionList, signList, n, w, q, barrettMultiplication, barrettDivision);

            Polynomial.polynomialSubtractionP(W, n * i, W, n * i, TC, n * i, n, q, barrettMultiplication, barrettDivision);
        }

        /* Obtain the Hash Symbol */
        hashFunction(cSignature, 0, W, message, 0, message.length, n, k, d, q);

        /* Check if Same with One from Signature */
        if (CommonFunction.memoryEqual(C, 0, cSignature, 0, Polynomial.HASH) == false)
        {
            return -3;
        }

        return 0;

    }

    /*****************************************************************************************************
     * Description:	Extracts the Original Message and Checks Whether the Generated Signature is Valid for
     * 				A Given Signature Package for Provably-Secure qTESLA Security Category-1
     *
     * @param        signature                            Given Signature Package
     * @param        signatureOffset                        Starting Point of the Given Signature Package
     * @param        signatureLength                        Length of the Given Signature Package
     * @param        message                                Original (Signed) Message
     * @param        publicKey                            Public Key
     *
     * @return 0                                    Valid Signature
     * 				< 0									Invalid Signature
     *****************************************************************************************************/
    static int verifyingPI(
        byte[] message,
        final byte[] signature, int signatureOffset, int signatureLength,
        final byte[] publicKey
    )
    {

        return verifying(

            message,
            signature, signatureOffset, signatureLength,
            publicKey,
            Parameter.N_I_P, Parameter.K_I_P, Parameter.W_I_P,
            Parameter.Q_I_P, Parameter.Q_INVERSE_I_P, Parameter.Q_LOGARITHM_I_P,
            Parameter.B_I_P, Parameter.D_I_P, Parameter.U_I_P, Polynomial.SIGNATURE_I_P,
            Parameter.GENERATOR_A_I_P, Parameter.INVERSE_NUMBER_THEORETIC_TRANSFORM_I_P,
            Parameter.BARRETT_MULTIPLICATION_I_P, Parameter.BARRETT_DIVISION_I_P,
            PolynomialProvablySecure.ZETA_I_P

        );

    }

    /*****************************************************************************************************
     * Description:	Extracts the Original Message and Checks Whether the Generated Signature is Valid for
     * 				A Given Signature Package for Provably-Secure qTESLA Security Category-3
     *
     * @param        signature                            Given Signature Package
     * @param        signatureOffset                        Starting Point of the Given Signature Package
     * @param        signatureLength                        Length of the Given Signature Package
     * @param        message                                Original (Signed) Message
     * @param        publicKey                            Public Key
     *
     * @return 0                                    Valid Signature
     * 				< 0									Invalid Signature
     *****************************************************************************************************/
    static int verifyingPIII(

        byte[] message,
        final byte[] signature, int signatureOffset, int signatureLength,
        final byte[] publicKey

    )
    {
        return verifying(
            message,
            signature, signatureOffset, signatureLength,
            publicKey,
            Parameter.N_III_P, Parameter.K_III_P, Parameter.W_III_P,
            Parameter.Q_III_P, Parameter.Q_INVERSE_III_P, Parameter.Q_LOGARITHM_III_P,
            Parameter.B_III_P, Parameter.D_III_P, Parameter.U_III_P, Polynomial.SIGNATURE_III_P,
            Parameter.GENERATOR_A_III_P, Parameter.INVERSE_NUMBER_THEORETIC_TRANSFORM_III_P,
            Parameter.BARRETT_MULTIPLICATION_III_P, Parameter.BARRETT_DIVISION_III_P,
            PolynomialProvablySecure.ZETA_III_P
        );
    }

}
