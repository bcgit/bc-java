package org.bouncycastle.pqc.crypto.qteslarnd1;

class Pack
{

    /*******************************************************************************************************************************************************
     * Description:	Encode Private Key for Heuristic qTESLA Security Category-1
     *
     * @param        privateKey                Private Key
     * @param        secretPolynomial        Coefficients of the Secret Polynomial
     * @param        errorPolynomial            Coefficients of the Error Polynomial
     * @param        seed                    Kappa-Bit Seed
     * @param        seedOffset                Starting Point of the Kappa-Bit Seed
     *
     * @return none
     *******************************************************************************************************************************************************/
    public static void encodePrivateKeyI(byte[] privateKey, final int[] secretPolynomial, final int[] errorPolynomial, final byte[] seed, int seedOffset)
    {

        int j = 0;

        for (int i = 0; i < Parameter.N_I; i += 4)
        {

            privateKey[j + 0] = (byte)secretPolynomial[i + 0];
            privateKey[j + 1] = (byte)(((secretPolynomial[i + 0] >> 8) & 0x03) | (secretPolynomial[i + 1] << 2));
            privateKey[j + 2] = (byte)(((secretPolynomial[i + 1] >> 6) & 0x0F) | (secretPolynomial[i + 2] << 4));
            privateKey[j + 3] = (byte)(((secretPolynomial[i + 2] >> 4) & 0x3F) | (secretPolynomial[i + 3] << 6));
            privateKey[j + 4] = (byte)(secretPolynomial[i + 3] >> 2);

            j += 5;

        }

        for (int i = 0; i < Parameter.N_I; i += 4)
        {

            privateKey[j + 0] = (byte)errorPolynomial[i + 0];
            privateKey[j + 1] = (byte)(((errorPolynomial[i + 0] >> 8) & 0x03) | (errorPolynomial[i + 1] << 2));
            privateKey[j + 2] = (byte)(((errorPolynomial[i + 1] >> 6) & 0x0F) | (errorPolynomial[i + 2] << 4));
            privateKey[j + 3] = (byte)(((errorPolynomial[i + 2] >> 4) & 0x3F) | (errorPolynomial[i + 3] << 6));
            privateKey[j + 4] = (byte)(errorPolynomial[i + 3] >> 2);

            j += 5;

        }

        System.arraycopy(seed, seedOffset, privateKey, Parameter.N_I * Parameter.S_BIT_I * 2 / Const.BYTE_SIZE, Polynomial.SEED * 2);

    }

    /*************************************************************************************************************************************************************
     * Description:	Encode Private Key for Heuristic qTESLA Security Category-3 (Option for Size)
     *
     * @param        privateKey                Private Key
     * @param        secretPolynomial        Coefficients of the Secret Polynomial
     * @param        errorPolynomial            Coefficients of the Error Polynomial
     * @param        seed                    Kappa-Bit Seed
     * @param        seedOffset                Starting Point of the Kappa-Bit Seed
     *
     * @return none
     *************************************************************************************************************************************************************/
    public static void encodePrivateKeyIIISize(byte[] privateKey, final int[] secretPolynomial, final int[] errorPolynomial, final byte[] seed, int seedOffset)
    {

        for (int i = 0; i < Parameter.N_III_SIZE; i++)
        {

            privateKey[i] = (byte)secretPolynomial[i];

        }

        for (int i = 0; i < Parameter.N_III_SIZE; i++)
        {

            privateKey[Parameter.N_III_SIZE + i] = (byte)errorPolynomial[i];

        }

        System.arraycopy(seed, seedOffset, privateKey, Parameter.N_III_SIZE * Parameter.S_BIT_III_SIZE * 2 / Const.BYTE_SIZE, Polynomial.SEED * 2);

    }

    /***********************************************************************************************************************************************************************************
     * Description:	Encode Private Key for Heuristic qTESLA Security Category-3 (Option for Speed)
     *
     * @param        privateKey                Private Key
     * @param        secretPolynomial        Coefficients of the Secret Polynomial
     * @param        errorPolynomial            Coefficients of the Error Polynomial
     * @param        seed                    Kappa-Bit Seed
     * @param        seedOffset                Starting Point of the Kappa-Bit Seed
     *
     * @return none
     ***********************************************************************************************************************************************************************************/
    public static void encodePrivateKeyIIISpeed(byte[] privateKey, final int[] secretPolynomial, final int[] errorPolynomial, final byte[] seed, int seedOffset)
    {

        int j = 0;

        for (int i = 0; i < Parameter.N_III_SPEED; i += 8)
        {

            privateKey[j + 0] = (byte)secretPolynomial[i + 0];
            privateKey[j + 1] = (byte)(((secretPolynomial[i + 0] >> 8) & 0x01) | (secretPolynomial[i + 1] << 1));
            privateKey[j + 2] = (byte)(((secretPolynomial[i + 1] >> 7) & 0x03) | (secretPolynomial[i + 2] << 2));
            privateKey[j + 3] = (byte)(((secretPolynomial[i + 2] >> 6) & 0x07) | (secretPolynomial[i + 3] << 3));
            privateKey[j + 4] = (byte)(((secretPolynomial[i + 3] >> 5) & 0x0F) | (secretPolynomial[i + 4] << 4));
            privateKey[j + 5] = (byte)(((secretPolynomial[i + 4] >> 4) & 0x1F) | (secretPolynomial[i + 5] << 5));
            privateKey[j + 6] = (byte)(((secretPolynomial[i + 5] >> 3) & 0x3F) | (secretPolynomial[i + 6] << 6));
            privateKey[j + 7] = (byte)(((secretPolynomial[i + 6] >> 2) & 0x7F) | (secretPolynomial[i + 7] << 7));
            privateKey[j + 8] = (byte)(secretPolynomial[i + 7] >> 1);

            j += 9;

        }

        for (int i = 0; i < Parameter.N_III_SPEED; i += 8)
        {

            privateKey[j + 0] = (byte)errorPolynomial[i + 0];
            privateKey[j + 1] = (byte)(((errorPolynomial[i + 0] >> 8) & 0x01) | (errorPolynomial[i + 1] << 1));
            privateKey[j + 2] = (byte)(((errorPolynomial[i + 1] >> 7) & 0x03) | (errorPolynomial[i + 2] << 2));
            privateKey[j + 3] = (byte)(((errorPolynomial[i + 2] >> 6) & 0x07) | (errorPolynomial[i + 3] << 3));
            privateKey[j + 4] = (byte)(((errorPolynomial[i + 3] >> 5) & 0x0F) | (errorPolynomial[i + 4] << 4));
            privateKey[j + 5] = (byte)(((errorPolynomial[i + 4] >> 4) & 0x1F) | (errorPolynomial[i + 5] << 5));
            privateKey[j + 6] = (byte)(((errorPolynomial[i + 5] >> 3) & 0x3F) | (errorPolynomial[i + 6] << 6));
            privateKey[j + 7] = (byte)(((errorPolynomial[i + 6] >> 2) & 0x7F) | (errorPolynomial[i + 7] << 7));
            privateKey[j + 8] = (byte)(errorPolynomial[i + 7] >> 1);

            j += 9;

        }

        System.arraycopy(seed, seedOffset, privateKey, Parameter.N_III_SPEED * Parameter.S_BIT_III_SPEED * 2 / Const.BYTE_SIZE, Polynomial.SEED * 2);

    }

    /*******************************************************************************************************************************
     * Description:	Decode Private Key for Heuristic qTESLA Security Category-1
     *
     * @param        seed                    Kappa-Bit Seed
     * @param        secretPolynomial        Coefficients of the Secret Polynomial
     * @param        errorPolynomial            Coefficients of the Error Polynomial
     * @param        privateKey                Private Key
     *
     * @return none
     *******************************************************************************************************************************/
    public static void decodePrivateKeyI(byte[] seed, short[] secretPolynomial, short[] errorPolynomial, final byte[] privateKey)
    {

        int j = 0;
        int temporary = 0;

        for (int i = 0; i < Parameter.N_I; i += 4)
        {

            temporary = privateKey[j + 0] & 0xFF;
            secretPolynomial[i + 0] = (short)temporary;
            temporary = privateKey[j + 1] & 0xFF;
            temporary = (temporary << 30) >> 22;
            secretPolynomial[i + 0] |= (short)temporary;

            temporary = privateKey[j + 1] & 0xFF;
            temporary = temporary >> 2;
            secretPolynomial[i + 1] = (short)temporary;
            temporary = privateKey[j + 2] & 0xFF;
            temporary = (temporary << 28) >> 22;
            secretPolynomial[i + 1] |= (short)temporary;

            temporary = privateKey[j + 2] & 0xFF;
            temporary = temporary >> 4;
            secretPolynomial[i + 2] = (short)temporary;
            temporary = privateKey[j + 3] & 0xFF;
            temporary = (temporary << 26) >> 22;
            secretPolynomial[i + 2] |= (short)temporary;

            temporary = privateKey[j + 3] & 0xFF;
            temporary = temporary >> 6;
            secretPolynomial[i + 3] = (short)temporary;
            temporary = privateKey[j + 4];
            temporary = (short)temporary << 2;
            secretPolynomial[i + 3] |= (short)temporary;

            j += 5;

        }

        for (int i = 0; i < Parameter.N_I; i += 4)
        {

            temporary = privateKey[j + 0] & 0xFF;
            errorPolynomial[i + 0] = (short)temporary;
            temporary = privateKey[j + 1] & 0xFF;
            temporary = (temporary << 30) >> 22;
            errorPolynomial[i + 0] |= (short)temporary;

            temporary = privateKey[j + 1] & 0xFF;
            temporary = temporary >> 2;
            errorPolynomial[i + 1] = (short)temporary;
            temporary = privateKey[j + 2] & 0xFF;
            temporary = (temporary << 28) >> 22;
            errorPolynomial[i + 1] |= (short)temporary;

            temporary = privateKey[j + 2] & 0xFF;
            temporary = temporary >> 4;
            errorPolynomial[i + 2] = (short)temporary;
            temporary = privateKey[j + 3] & 0xFF;
            temporary = (temporary << 26) >> 22;
            errorPolynomial[i + 2] |= (short)temporary;

            temporary = privateKey[j + 3] & 0xFF;
            temporary = temporary >> 6;
            errorPolynomial[i + 3] = (short)temporary;
            temporary = privateKey[j + 4];
            temporary = (short)temporary << 2;
            errorPolynomial[i + 3] |= (short)temporary;

            j += 5;

        }

        System.arraycopy(privateKey, Parameter.N_I * Parameter.S_BIT_I * 2 / Const.BYTE_SIZE, seed, 0, Polynomial.SEED * 2);

    }

    /*************************************************************************************************************************************
     * Description:	Decode Private Key for Heuristic qTESLA Security Category-3 (Option for Size)
     *
     * @param        seed                    Kappa-Bit Seed
     * @param        secretPolynomial        Coefficients of the Secret Polynomial
     * @param        errorPolynomial            Coefficients of the Error Polynomial
     * @param        privateKey                Private Key
     *
     * @return none
     *************************************************************************************************************************************/
    public static void decodePrivateKeyIIISize(byte[] seed, short[] secretPolynomial, short[] errorPolynomial, final byte[] privateKey)
    {

        for (int i = 0; i < Parameter.N_III_SIZE; i++)
        {

            secretPolynomial[i] = privateKey[i];

        }

        for (int i = 0; i < Parameter.N_III_SIZE; i++)
        {

            errorPolynomial[i] = privateKey[Parameter.N_III_SIZE + i];

        }

        System.arraycopy(privateKey, Parameter.N_III_SIZE * Parameter.S_BIT_III_SIZE * 2 / Const.BYTE_SIZE, seed, 0, Polynomial.SEED * 2);

    }

    /**************************************************************************************************************************************
     * Description:	Decode Private Key for Heuristic qTESLA Security Category-3 (Option for Speed)
     *
     * @param        seed                    Kappa-Bit Seed
     * @param        secretPolynomial        Coefficients of the Secret Polynomial
     * @param        errorPolynomial            Coefficients of the Error Polynomial
     * @param        privateKey                Private Key
     *
     * @return none
     **************************************************************************************************************************************/
    public static void decodePrivateKeyIIISpeed(byte[] seed, short[] secretPolynomial, short[] errorPolynomial, final byte[] privateKey)
    {

        int j = 0;
        int temporary = 0;

        for (int i = 0; i < Parameter.N_III_SPEED; i += 8)
        {

            temporary = privateKey[j + 0] & 0xFF;
            secretPolynomial[i + 0] = (short)temporary;
            temporary = privateKey[j + 1] & 0xFF;
            temporary = (temporary << 31) >> 23;
            secretPolynomial[i + 0] |= (short)temporary;

            temporary = privateKey[j + 1] & 0xFF;
            temporary = temporary >> 1;
            secretPolynomial[i + 1] = (short)temporary;
            temporary = privateKey[j + 2] & 0xFF;
            temporary = (temporary << 30) >> 23;
            secretPolynomial[i + 1] |= (short)temporary;

            temporary = privateKey[j + 2] & 0xFF;
            temporary = temporary >> 2;
            secretPolynomial[i + 2] = (short)temporary;
            temporary = privateKey[j + 3] & 0xFF;
            temporary = (temporary << 29) >> 23;
            secretPolynomial[i + 2] |= (short)temporary;

            temporary = privateKey[j + 3] & 0xFF;
            temporary = temporary >> 3;
            secretPolynomial[i + 3] = (short)temporary;
            temporary = privateKey[j + 4] & 0xFF;
            temporary = (temporary << 28) >> 23;
            secretPolynomial[i + 3] |= (short)temporary;

            temporary = privateKey[j + 4] & 0xFF;
            temporary = temporary >> 4;
            secretPolynomial[i + 4] = (short)temporary;
            temporary = privateKey[j + 5] & 0xFF;
            temporary = (temporary << 27) >> 23;
            secretPolynomial[i + 4] |= (short)temporary;

            temporary = privateKey[j + 5] & 0xFF;
            temporary = temporary >> 5;
            secretPolynomial[i + 5] = (short)temporary;
            temporary = privateKey[j + 6] & 0xFF;
            temporary = (temporary << 26) >> 23;
            secretPolynomial[i + 5] |= (short)temporary;

            temporary = privateKey[j + 6] & 0xFF;
            temporary = temporary >> 6;
            secretPolynomial[i + 6] = (short)temporary;
            temporary = privateKey[j + 7] & 0xFF;
            temporary = (temporary << 25) >> 23;
            secretPolynomial[i + 6] |= (short)temporary;

            temporary = privateKey[j + 7] & 0xFF;
            temporary = temporary >> 7;
            secretPolynomial[i + 7] = (short)temporary;
            temporary = privateKey[j + 8];
            temporary = (short)temporary << 1;
            secretPolynomial[i + 7] |= (short)temporary;

            j += 9;

        }

        for (int i = 0; i < Parameter.N_III_SPEED; i += 8)
        {

            temporary = privateKey[j + 0] & 0xFF;
            errorPolynomial[i + 0] = (short)temporary;
            temporary = privateKey[j + 1] & 0xFF;
            temporary = (temporary << 31) >> 23;
            errorPolynomial[i + 0] |= (short)temporary;

            temporary = privateKey[j + 1] & 0xFF;
            temporary = temporary >> 1;
            errorPolynomial[i + 1] = (short)temporary;
            temporary = privateKey[j + 2] & 0xFF;
            temporary = (temporary << 30) >> 23;
            errorPolynomial[i + 1] |= (short)temporary;

            temporary = privateKey[j + 2] & 0xFF;
            temporary = temporary >> 2;
            errorPolynomial[i + 2] = (short)temporary;
            temporary = privateKey[j + 3] & 0xFF;
            temporary = (temporary << 29) >> 23;
            errorPolynomial[i + 2] |= (short)temporary;

            temporary = privateKey[j + 3] & 0xFF;
            temporary = temporary >> 3;
            errorPolynomial[i + 3] = (short)temporary;
            temporary = privateKey[j + 4] & 0xFF;
            temporary = (temporary << 28) >> 23;
            errorPolynomial[i + 3] |= (short)temporary;

            temporary = privateKey[j + 4] & 0xFF;
            temporary = temporary >> 4;
            errorPolynomial[i + 4] = (short)temporary;
            temporary = privateKey[j + 5] & 0xFF;
            temporary = (temporary << 27) >> 23;
            errorPolynomial[i + 4] |= (short)temporary;

            temporary = privateKey[j + 5] & 0xFF;
            temporary = temporary >> 5;
            errorPolynomial[i + 5] = (short)temporary;
            temporary = privateKey[j + 6] & 0xFF;
            temporary = (temporary << 26) >> 23;
            errorPolynomial[i + 5] |= (short)temporary;

            temporary = privateKey[j + 6] & 0xFF;
            temporary = temporary >> 6;
            errorPolynomial[i + 6] = (short)temporary;
            temporary = privateKey[j + 7] & 0xFF;
            temporary = (temporary << 25) >> 23;
            errorPolynomial[i + 6] |= (short)temporary;

            temporary = privateKey[j + 7] & 0xFF;
            temporary = temporary >> 7;
            errorPolynomial[i + 7] = (short)temporary;
            temporary = privateKey[j + 8];
            temporary = (short)temporary << 1;
            errorPolynomial[i + 7] |= (short)temporary;

            j += 9;

        }

        System.arraycopy(privateKey, Parameter.N_III_SPEED * Parameter.S_BIT_III_SPEED * 2 / Const.BYTE_SIZE, seed, 0, Polynomial.SEED * 2);

    }

    /********************************************************************************************************************************************************************
     * Description:	Pack Private Key for Provably-Secure qTESLA Security Category-1 and Security Category-3
     *
     * @param        privateKey                Private Key
     * @param        secretPolynomial        Coefficients of the Secret Polynomial
     * @param        errorPolynomial            Coefficients of the Error Polynomial
     * @param        seed                    Kappa-Bit Seed
     * @param        seedOffset                Starting Point of the Kappa-Bit Seed
     * @param        n                        Polynomial Degree
     * @param        k                        Number of Ring-Learning-With-Errors Samples
     *
     * @return none
     ********************************************************************************************************************************************************************/
    public static void packPrivateKey(byte[] privateKey, final long[] secretPolynomial, final long[] errorPolynomial, final byte[] seed, int seedOffset, int n, int k)
    {

        for (int i = 0; i < n; i++)
        {

            privateKey[i] = (byte)secretPolynomial[i];

        }

        for (int j = 0; j < k; j++)
        {

            for (int i = 0; i < n; i++)
            {

                privateKey[n + j * n + i] = (byte)errorPolynomial[j * n + i];

            }

        }

        System.arraycopy(seed, seedOffset, privateKey, n + k * n, Polynomial.SEED * 2);

    }

    /**************************************************************************************************************************************************
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
     **************************************************************************************************************************************************/
    public static void encodePublicKey(byte[] publicKey, final int[] T, final byte[] seedA, int seedAOffset, int n, int qLogarithm)
    {

        int j = 0;

        for (int i = 0; i < n * qLogarithm / Const.INT_SIZE; i += qLogarithm)
        {

            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 0), (int)(T[j + 0] | (T[j + 1] << 23)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 1), (int)((T[j + 1] >> 9) | (T[j + 2] << 14)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 2), (int)((T[j + 2] >> 18) | (T[j + 3] << 5) | (T[j + 4] << 28)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 3), (int)((T[j + 4] >> 4) | (T[j + 5] << 19)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 4), (int)((T[j + 5] >> 13) | (T[j + 6] << 10)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 5), (int)((T[j + 6] >> 22) | (T[j + 7] << 1) | (T[j + 8] << 24)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 6), (int)((T[j + 8] >> 8) | (T[j + 9] << 15)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 7), (int)((T[j + 9] >> 17) | (T[j + 10] << 6) | (T[j + 11] << 29)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 8), (int)((T[j + 11] >> 3) | (T[j + 12] << 20)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 9), (int)((T[j + 12] >> 12) | (T[j + 13] << 11)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 10), (int)((T[j + 13] >> 21) | (T[j + 14] << 2) | (T[j + 15] << 25)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 11), (int)((T[j + 15] >> 7) | (T[j + 16] << 16)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 12), (int)((T[j + 16] >> 16) | (T[j + 17] << 7) | (T[j + 18] << 30)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 13), (int)((T[j + 18] >> 2) | (T[j + 19] << 21)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 14), (int)((T[j + 19] >> 11) | (T[j + 20] << 12)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 15), (int)((T[j + 20] >> 20) | (T[j + 21] << 3) | (T[j + 22] << 26)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 16), (int)((T[j + 22] >> 6) | (T[j + 23] << 17)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 17), (int)((T[j + 23] >> 15) | (T[j + 24] << 8) | (T[j + 25] << 31)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 18), (int)((T[j + 25] >> 1) | (T[j + 26] << 22)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 19), (int)((T[j + 26] >> 10) | (T[j + 27] << 13)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 20), (int)((T[j + 27] >> 19) | (T[j + 28] << 4) | (T[j + 29] << 27)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 21), (int)((T[j + 29] >> 5) | (T[j + 30] << 18)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 22), (int)((T[j + 30] >> 14) | (T[j + 31] << 9)));

            j += Const.INT_SIZE;

        }

        System.arraycopy(seedA, seedAOffset, publicKey, n * qLogarithm / Const.BYTE_SIZE, Polynomial.SEED);

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
    public static void encodePublicKeyIIISpeed(byte[] publicKey, final int[] T, final byte[] seedA, int seedAOffset)
    {

        int j = 0;

        for (int i = 0; i < Parameter.N_III_SPEED * Parameter.Q_LOGARITHM_III_SPEED / Const.INT_SIZE; i += (Parameter.Q_LOGARITHM_III_SPEED / Const.BYTE_SIZE))
        {

            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 0), (int)(T[j + 0] | (T[j + 1] << 24)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 1), (int)((T[j + 1] >> 8) | (T[j + 2] << 16)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 2), (int)((T[j + 2] >> 16) | (T[j + 3] << 8)));

            j += Const.INT_SIZE / Const.BYTE_SIZE;

        }

        System.arraycopy(seedA, seedAOffset, publicKey, Parameter.N_III_SPEED * Parameter.Q_LOGARITHM_III_SPEED / Const.BYTE_SIZE, Polynomial.SEED);

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
    public static void encodePublicKeyIP(byte[] publicKey, final long[] T, final byte[] seedA, int seedAOffset)
    {

        int j = 0;

        for (int i = 0; i < Parameter.N_I_P * Parameter.K_I_P * Parameter.Q_LOGARITHM_I_P / Const.INT_SIZE; i += Parameter.Q_LOGARITHM_I_P)
        {

            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 0), (int)(T[j + 0] | (T[j + 1] << 29)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 1), (int)((T[j + 1] >> 3) | (T[j + 2] << 26)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 2), (int)((T[j + 2] >> 6) | (T[j + 3] << 23)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 3), (int)((T[j + 3] >> 9) | (T[j + 4] << 20)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 4), (int)((T[j + 4] >> 12) | (T[j + 5] << 17)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 5), (int)((T[j + 5] >> 15) | (T[j + 6] << 14)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 6), (int)((T[j + 6] >> 18) | (T[j + 7] << 11)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 7), (int)((T[j + 7] >> 21) | (T[j + 8] << 8)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 8), (int)((T[j + 8] >> 24) | (T[j + 9] << 5)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 9), (int)((T[j + 9] >> 27) | (T[j + 10] << 2) | (T[j + 11] << 31)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 10), (int)((T[j + 11] >> 1) | (T[j + 12] << 28)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 11), (int)((T[j + 12] >> 4) | (T[j + 13] << 25)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 12), (int)((T[j + 13] >> 7) | (T[j + 14] << 22)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 13), (int)((T[j + 14] >> 10) | (T[j + 15] << 19)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 14), (int)((T[j + 15] >> 13) | (T[j + 16] << 16)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 15), (int)((T[j + 16] >> 16) | (T[j + 17] << 13)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 16), (int)((T[j + 17] >> 19) | (T[j + 18] << 10)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 17), (int)((T[j + 18] >> 22) | (T[j + 19] << 7)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 18), (int)((T[j + 19] >> 25) | (T[j + 20] << 4)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 19), (int)((T[j + 20] >> 28) | (T[j + 21] << 1) | (T[j + 22] << 30)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 20), (int)((T[j + 22] >> 2) | (T[j + 23] << 27)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 21), (int)((T[j + 23] >> 5) | (T[j + 24] << 24)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 22), (int)((T[j + 24] >> 8) | (T[j + 25] << 21)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 23), (int)((T[j + 25] >> 11) | (T[j + 26] << 18)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 24), (int)((T[j + 26] >> 14) | (T[j + 27] << 15)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 25), (int)((T[j + 27] >> 17) | (T[j + 28] << 12)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 26), (int)((T[j + 28] >> 20) | (T[j + 29] << 9)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 27), (int)((T[j + 29] >> 23) | (T[j + 30] << 6)));
            CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + 28), (int)((T[j + 30] >> 26) | (T[j + 31] << 3)));

            j += Const.INT_SIZE;

        }

        System.arraycopy(seedA, seedAOffset, publicKey, Parameter.N_I_P * Parameter.K_I_P * Parameter.Q_LOGARITHM_I_P / Const.BYTE_SIZE, Polynomial.SEED);

    }

    /*************************************************************************************************************************************************************************************
     * Description:	Encode Public Key for Provably-Secure qTESLA Security Category-3
     *
     * @param        publicKey            Public Key
     * @param        T                    T_1, ..., T_k
     * @param        seedA                Seed Used to Generate the Polynomials a_i for i = 1, ..., k
     * @param        seedAOffset            Starting Point of the Seed A
     *
     * @return none
     *************************************************************************************************************************************************************************************/
    public static void encodePublicKeyIIIP(byte[] publicKey, final long[] T, final byte[] seedA, int seedAOffset)
    {

        int j = 0;

        for (int i = 0; i < Parameter.N_III_P * Parameter.K_III_P * Parameter.Q_LOGARITHM_III_P / Const.INT_SIZE; i += Parameter.Q_LOGARITHM_III_P)
        {

            for (int index = 0; index < Parameter.Q_LOGARITHM_III_P; index++)
            {

                CommonFunction.store32(publicKey, Const.INT_SIZE / Const.BYTE_SIZE * (i + index), (int)((T[j + index] >> index) | (T[j + index + 1] << (Parameter.Q_LOGARITHM_III_P - index))));

            }

            j += Const.INT_SIZE;

        }

        System.arraycopy(seedA, seedAOffset, publicKey, Parameter.N_III_P * Parameter.K_III_P * Parameter.Q_LOGARITHM_III_P / Const.BYTE_SIZE, Polynomial.SEED);

    }

    /****************************************************************************************************************************************
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
     ****************************************************************************************************************************************/
    public static void decodePublicKey(int[] publicKey, byte[] seedA, int seedAOffset, final byte[] publicKeyInput, int n, int qLogarithm)
    {

        int j = 0;

        int mask = (1 << qLogarithm) - 1;

        for (int i = 0; i < n; i += Const.INT_SIZE)
        {

            publicKey[i + 0] = CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 0)) & mask;

            publicKey[i + 1] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 0)) >>> 23) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 1)) << 9)) & mask;

            publicKey[i + 2] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 1)) >>> 14) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 2)) << 18)) & mask;

            publicKey[i + 3] = (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 2)) >>> 5) & mask;

            publicKey[i + 4] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 2)) >>> 28) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 3)) << 4)) & mask;

            publicKey[i + 5] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 3)) >>> 19) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 4)) << 13)) & mask;

            publicKey[i + 6] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 4)) >>> 10) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 5)) << 22)) & mask;

            publicKey[i + 7] = (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 5)) >>> 1) & mask;

            publicKey[i + 8] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 5)) >>> 24) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 6)) << 8)) & mask;

            publicKey[i + 9] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 6)) >>> 15) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 7)) << 17)) & mask;

            publicKey[i + 10] = (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 7)) >>> 6) & mask;

            publicKey[i + 11] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 7)) >>> 29) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 8)) << 3)) & mask;

            publicKey[i + 12] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 8)) >>> 20) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 9)) << 12)) & mask;

            publicKey[i + 13] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 9)) >>> 11) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 10)) << 21)) & mask;

            publicKey[i + 14] = (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 10)) >>> 2) & mask;

            publicKey[i + 15] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 10)) >>> 25) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 11)) << 7)) & mask;

            publicKey[i + 16] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 11)) >>> 16) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 12)) << 16)) & mask;

            publicKey[i + 17] = (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 12)) >>> 7) & mask;

            publicKey[i + 18] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 12)) >>> 30) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 13)) << 2)) & mask;

            publicKey[i + 19] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 13)) >>> 21) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 14)) << 11)) & mask;

            publicKey[i + 20] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 14)) >>> 12) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 15)) << 20)) & mask;

            publicKey[i + 21] = (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 15)) >>> 3) & mask;

            publicKey[i + 22] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 15)) >>> 26) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 16)) << 6)) & mask;

            publicKey[i + 23] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 16)) >>> 17) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 17)) << 15)) & mask;

            publicKey[i + 24] = (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 17)) >>> 8) & mask;

            publicKey[i + 25] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 17)) >>> 31) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 18)) << 1)) & mask;

            publicKey[i + 26] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 18)) >>> 22) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 19)) << 10)) & mask;

            publicKey[i + 27] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 19)) >>> 13) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 20)) << 19)) & mask;

            publicKey[i + 28] = (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 20)) >>> 4) & mask;

            publicKey[i + 29] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 20)) >>> 27) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 21)) << 5)) & mask;

            publicKey[i + 30] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 21)) >>> 18) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 22)) << 14)) & mask;

            publicKey[i + 31] = CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 22)) >>> 9;

            j += qLogarithm;

        }

        System.arraycopy(publicKeyInput, n * qLogarithm / Const.BYTE_SIZE, seedA, seedAOffset, Polynomial.SEED);

    }

    /*************************************************************************************************************************************************
     * Description:	Decode Public Key for Heuristic qTESLA Security Category-3 (Option for Speed)
     *
     * @param        publicKey            Decoded Public Key
     * @param        seedA                Seed Used to Generate the Polynomials A_i for i = 1, ..., k
     * @param        seedAOffset            Starting Point of the Seed A
     * @param        publicKeyInput        Public Key to be Decoded
     *
     * @return none
     *************************************************************************************************************************************************/
    public static void decodePublicKeyIIISpeed(int[] publicKey, byte[] seedA, int seedAOffset, final byte[] publicKeyInput)
    {

        int j = 0;

        int mask = (1 << Parameter.Q_LOGARITHM_III_SPEED) - 1;

        for (int i = 0; i < Parameter.N_III_SPEED; i += Const.INT_SIZE / Const.BYTE_SIZE)
        {

            publicKey[i + 0] = CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 0)) & mask;

            publicKey[i + 1] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 0)) >>> 24) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 1)) << 8)) & mask;

            publicKey[i + 2] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 1)) >>> 16) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 2)) << 16)) & mask;

            publicKey[i + 3] = CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 2)) >>> 8;

            j += Parameter.Q_LOGARITHM_III_SPEED / Const.BYTE_SIZE;

        }

        System.arraycopy(publicKeyInput, Parameter.N_III_SPEED * Parameter.Q_LOGARITHM_III_SPEED / Const.BYTE_SIZE, seedA, seedAOffset, Polynomial.SEED);

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
    public static void decodePublicKeyIP(int[] publicKey, byte[] seedA, int seedAOffset, final byte[] publicKeyInput)
    {

        int j = 0;

        int mask = (1 << Parameter.Q_LOGARITHM_I_P) - 1;

        for (int i = 0; i < Parameter.N_I_P * Parameter.K_I_P; i += Const.INT_SIZE)
        {

            publicKey[i + 0] = CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 0)) & mask;

            publicKey[i + 1] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 0)) >>> 29) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 1)) << 3)) & mask;

            publicKey[i + 2] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 1)) >>> 26) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 2)) << 6)) & mask;

            publicKey[i + 3] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 2)) >>> 23) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 3)) << 9)) & mask;

            publicKey[i + 4] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 3)) >>> 20) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 4)) << 12)) & mask;

            publicKey[i + 5] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 4)) >>> 17) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 5)) << 15)) & mask;

            publicKey[i + 6] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 5)) >>> 14) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 6)) << 18)) & mask;

            publicKey[i + 7] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 6)) >>> 11) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 7)) << 21)) & mask;

            publicKey[i + 8] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 7)) >>> 8) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 8)) << 24)) & mask;

            publicKey[i + 9] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 8)) >>> 5) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 9)) << 27)) & mask;

            publicKey[i + 10] = (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 9)) >>> 2) & mask;

            publicKey[i + 11] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 9)) >>> 31) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 10)) << 1)) & mask;

            publicKey[i + 12] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 10)) >>> 28) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 11)) << 4)) & mask;

            publicKey[i + 13] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 11)) >>> 25) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 12)) << 7)) & mask;

            publicKey[i + 14] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 12)) >>> 22) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 13)) << 10)) & mask;

            publicKey[i + 15] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 13)) >>> 19) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 14)) << 13)) & mask;

            publicKey[i + 16] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 14)) >>> 16) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 15)) << 16)) & mask;

            publicKey[i + 17] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 15)) >>> 13) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 16)) << 19)) & mask;

            publicKey[i + 18] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 16)) >>> 10) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 17)) << 22)) & mask;

            publicKey[i + 19] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 17)) >>> 7) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 18)) << 25)) & mask;

            publicKey[i + 20] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 18)) >>> 4) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 19)) << 28)) & mask;

            publicKey[i + 21] = (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 19)) >>> 1) & mask;

            publicKey[i + 22] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 19)) >>> 30) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 20)) << 2)) & mask;

            publicKey[i + 23] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 20)) >>> 27) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 21)) << 5)) & mask;

            publicKey[i + 24] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 21)) >>> 24) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 22)) << 8)) & mask;

            publicKey[i + 25] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 22)) >>> 21) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 23)) << 11)) & mask;

            publicKey[i + 26] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 23)) >>> 18) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 24)) << 14)) & mask;

            publicKey[i + 27] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 24)) >>> 15) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 25)) << 17)) & mask;

            publicKey[i + 28] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 25)) >>> 12) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 26)) << 20)) & mask;

            publicKey[i + 29] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 26)) >>> 9) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 27)) << 23)) & mask;

            publicKey[i + 30] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 27)) >>> 6) |
                (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 28)) << 26)) & mask;

            publicKey[i + 31] = CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + 28)) >>> 3;

            j += Parameter.Q_LOGARITHM_I_P;

        }

        System.arraycopy(publicKeyInput, Parameter.N_I_P * Parameter.K_I_P * Parameter.Q_LOGARITHM_I_P / Const.BYTE_SIZE, seedA, seedAOffset, Polynomial.SEED);

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
    public static void decodePublicKeyIIIP(int[] publicKey, byte[] seedA, int seedAOffset, final byte[] publicKeyInput)
    {

        int j = 0;

        int mask = (1 << Parameter.Q_LOGARITHM_III_P) - 1;

        for (int i = 0; i < Parameter.N_III_P * Parameter.K_III_P; i += Const.INT_SIZE)
        {

            publicKey[i] = CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * j) & mask;

            for (int index = 1; index < Parameter.Q_LOGARITHM_III_P; index++)
            {

                publicKey[i + index] = ((CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + index - 1)) >>> (Const.INT_SIZE - index)) |
                    (CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + index)) << index)) & mask;

            }

            publicKey[i + Parameter.Q_LOGARITHM_III_P] = CommonFunction.load32(publicKeyInput, Const.INT_SIZE / Const.BYTE_SIZE * (j + Parameter.Q_LOGARITHM_III_P - 1)) >>> 1;

            j += Parameter.Q_LOGARITHM_III_P;

        }

        System.arraycopy(publicKeyInput, Parameter.N_III_P * Parameter.K_III_P * Parameter.Q_LOGARITHM_III_P / Const.BYTE_SIZE, seedA, seedAOffset, Polynomial.SEED);

    }


    /***************************************************************************************************************************************************************************************************************
     * Description:	Encode Signature for Heuristic qTESLA Security Category-1 and Category-3 (Option for Size)
     *
     * @param        signature            Output Package Containing Signature
     * @param        signatureOffset        Starting Point of the Output Package Containing Signature
     * @param        C
     * @param        cOffset
     * @param        Z
     * @param        n                    Polynomial Degree
     * @param        d                    Number of Rounded Bits
     *
     * @return none
     ***************************************************************************************************************************************************************************************************************/
    public static void encodeSignature(byte[] signature, int signatureOffset, byte[] C, int cOffset, int[] Z, int n, int d)
    {

        int j = 0;

        for (int i = 0; i < (n * d / Const.INT_SIZE); i += d)
        {

            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 0), (int)(((Z[j + 0] & ((1 << 21) - 1))) | (Z[j + 1] << 21)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 1), (int)(((Z[j + 1] >>> 11) & ((1 << 10) - 1)) | ((Z[j + 2] & ((1 << 21) - 1)) << 10) | (Z[j + 3] << 31)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 2), (int)((((Z[j + 3] >>> 1) & ((1 << 20) - 1))) | (Z[j + 4] << 20)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 3), (int)(((Z[j + 4] >>> 12) & ((1 << 9) - 1)) | ((Z[j + 5] & ((1 << 21) - 1)) << 9) | (Z[j + 6] << 30)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 4), (int)((((Z[j + 6] >>> 2) & ((1 << 19) - 1))) | (Z[j + 7] << 19)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 5), (int)(((Z[j + 7] >>> 13) & ((1 << 8) - 1)) | ((Z[j + 8] & ((1 << 21) - 1)) << 8) | (Z[j + 9] << 29)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 6), (int)((((Z[j + 9] >>> 3) & ((1 << 18) - 1))) | (Z[j + 10] << 18)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 7), (int)(((Z[j + 10] >>> 14) & ((1 << 7) - 1)) | ((Z[j + 11] & ((1 << 21) - 1)) << 7) | (Z[j + 12] << 28)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 8), (int)((((Z[j + 12] >>> 4) & ((1 << 17) - 1))) | (Z[j + 13] << 17)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 9), (int)(((Z[j + 13] >>> 15) & ((1 << 6) - 1)) | ((Z[j + 14] & ((1 << 21) - 1)) << 6) | (Z[j + 15] << 27)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 10), (int)((((Z[j + 15] >>> 5) & ((1 << 16) - 1))) | (Z[j + 16] << 16)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 11), (int)(((Z[j + 16] >>> 16) & ((1 << 5) - 1)) | ((Z[j + 17] & ((1 << 21) - 1)) << 5) | (Z[j + 18] << 26)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 12), (int)((((Z[j + 18] >>> 6) & ((1 << 15) - 1))) | (Z[j + 19] << 15)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 13), (int)(((Z[j + 19] >>> 17) & ((1 << 4) - 1)) | ((Z[j + 20] & ((1 << 21) - 1)) << 4) | (Z[j + 21] << 25)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 14), (int)((((Z[j + 21] >>> 7) & ((1 << 14) - 1))) | (Z[j + 22] << 14)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 15), (int)(((Z[j + 22] >>> 18) & ((1 << 3) - 1)) | ((Z[j + 23] & ((1 << 21) - 1)) << 3) | (Z[j + 24] << 24)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 16), (int)((((Z[j + 24] >>> 8) & ((1 << 13) - 1))) | (Z[j + 25] << 13)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 17), (int)(((Z[j + 25] >>> 19) & ((1 << 2) - 1)) | ((Z[j + 26] & ((1 << 21) - 1)) << 2) | (Z[j + 27] << 23)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 18), (int)((((Z[j + 27] >>> 9) & ((1 << 12) - 1))) | (Z[j + 28] << 12)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 19), (int)(((Z[j + 28] >>> 20) & ((1 << 1) - 1)) | ((Z[j + 29] & ((1 << 21) - 1)) << 1) | (Z[j + 30] << 22)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 20), (int)((((Z[j + 30] >>> 10) & ((1 << 11) - 1))) | (Z[j + 31] << 11)));

            j += Const.INT_SIZE;

        }

        System.arraycopy(C, cOffset, signature, signatureOffset + n * d / Const.BYTE_SIZE, Polynomial.HASH);

    }

    /*************************************************************************************************************************************************************************************************************
     * Description:	Encode Signature for Heuristic qTESLA Security Category-3 (Option for Speed)
     *
     * @param        signature            Output Package Containing Signature
     * @param        signatureOffset        Starting Point of the Output Package Containing Signature
     * @param        C
     * @param        cOffset
     * @param        Z
     *
     * @return none
     *************************************************************************************************************************************************************************************************************/
    public static void encodeSignatureIIISpeed(byte[] signature, int signatureOffset, byte[] C, int cOffset, int[] Z)
    {

        int j = 0;

        for (int i = 0; i < (Parameter.N_III_SPEED * Parameter.D_III_SPEED / Const.INT_SIZE); i += Parameter.D_III_SPEED / 2)
        {

            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 0), (int)(((Z[j + 0] & ((1 << 22) - 1))) | (Z[j + 1] << 22)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 1), (int)((((Z[j + 1] >>> 10) & ((1 << 12) - 1))) | (Z[j + 2] << 12)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 2), (int)(((Z[j + 2] >>> 20) & ((1 << 2) - 1)) | ((Z[j + 3] & ((1 << 22) - 1)) << 2) | (Z[j + 4] << 24)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 3), (int)((((Z[j + 4] >>> 8) & ((1 << 14) - 1))) | (Z[j + 5] << 14)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 4), (int)(((Z[j + 5] >>> 18) & ((1 << 4) - 1)) | ((Z[j + 6] & ((1 << 22) - 1)) << 4) | (Z[j + 7] << 26)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 5), (int)((((Z[j + 7] >>> 6) & ((1 << 16) - 1))) | (Z[j + 8] << 16)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 6), (int)(((Z[j + 8] >>> 16) & ((1 << 6) - 1)) | ((Z[j + 9] & ((1 << 22) - 1)) << 6) | (Z[j + 10] << 28)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 7), (int)((((Z[j + 10] >>> 4) & ((1 << 18) - 1))) | (Z[j + 11] << 18)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 8), (int)(((Z[j + 11] >>> 14) & ((1 << 8) - 1)) | ((Z[j + 12] & ((1 << 22) - 1)) << 8) | (Z[j + 13] << 30)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 9), (int)((((Z[j + 13] >>> 2) & ((1 << 20) - 1))) | (Z[j + 14] << 20)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 10), (int)((((Z[j + 14] >>> 12) & ((1 << 10) - 1))) | (Z[j + 15] << 10)));

            j += Const.INT_SIZE / 2;

        }

        System.arraycopy(C, cOffset, signature, signatureOffset + Parameter.N_III_SPEED * Parameter.D_III_SPEED / Const.BYTE_SIZE, Polynomial.HASH);

    }

    /*************************************************************************************************************************************************************************************************************
     * Description:	Encode Signature for Provably-Secure qTESLA Security Category-1
     *
     * @param        signature            Output Package Containing Signature
     * @param        signatureOffset        Starting Point of the Output Package Containing Signature
     * @param        C
     * @param        cOffset
     * @param        Z
     *
     * @return none
     *************************************************************************************************************************************************************************************************************/
    public static void encodeSignatureIP(byte[] signature, int signatureOffset, byte[] C, int cOffset, long[] Z)
    {

        int j = 0;

        for (int i = 0; i < (Parameter.N_III_SPEED * Parameter.D_III_SPEED / Const.INT_SIZE); i += Parameter.D_III_SPEED / 2)
        {

            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 0), (int)(((Z[j + 0] & ((1 << 22) - 1))) | (Z[j + 1] << 22)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 1), (int)((((Z[j + 1] >>> 10) & ((1 << 12) - 1))) | (Z[j + 2] << 12)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 2), (int)(((Z[j + 2] >>> 20) & ((1 << 2) - 1)) | ((Z[j + 3] & ((1 << 22) - 1)) << 2) | (Z[j + 4] << 24)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 3), (int)((((Z[j + 4] >>> 8) & ((1 << 14) - 1))) | (Z[j + 5] << 14)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 4), (int)(((Z[j + 5] >>> 18) & ((1 << 4) - 1)) | ((Z[j + 6] & ((1 << 22) - 1)) << 4) | (Z[j + 7] << 26)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 5), (int)((((Z[j + 7] >>> 6) & ((1 << 16) - 1))) | (Z[j + 8] << 16)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 6), (int)(((Z[j + 8] >>> 16) & ((1 << 6) - 1)) | ((Z[j + 9] & ((1 << 22) - 1)) << 6) | (Z[j + 10] << 28)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 7), (int)((((Z[j + 10] >>> 4) & ((1 << 18) - 1))) | (Z[j + 11] << 18)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 8), (int)(((Z[j + 11] >>> 14) & ((1 << 8) - 1)) | ((Z[j + 12] & ((1 << 22) - 1)) << 8) | (Z[j + 13] << 30)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 9), (int)((((Z[j + 13] >>> 2) & ((1 << 20) - 1))) | (Z[j + 14] << 20)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 10), (int)((((Z[j + 14] >>> 12) & ((1 << 10) - 1))) | (Z[j + 15] << 10)));

            j += Const.INT_SIZE / 2;

        }

        System.arraycopy(C, cOffset, signature, signatureOffset + Parameter.N_III_SPEED * Parameter.D_III_SPEED / Const.BYTE_SIZE, Polynomial.HASH);

    }

    /***************************************************************************************************************************************************************
     * Description:	Encode Signature for Provably-Secure qTESLA Security Category-3
     *
     * @param        signature            Output Package Containing Signature
     * @param        signatureOffset        Starting Point of the Output Package Containing Signature
     * @param        C
     * @param        cOffset
     * @param        Z
     *
     * @return none
     ***************************************************************************************************************************************************************/
    public static void encodeSignatureIIIP(byte[] signature, int signatureOffset, byte[] C, int cOffset, long[] Z)
    {

        int j = 0;

        for (int i = 0; i < (Parameter.N_III_P * Parameter.D_III_P / Const.INT_SIZE); i += Parameter.D_III_P / Const.BYTE_SIZE)
        {

            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 0), (int)(((Z[j + 0] & ((1 << 24) - 1))) | (Z[j + 1] << 24)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 1), (int)((((Z[j + 1] >>> 8) & ((1 << 16) - 1))) | (Z[j + 2] << 16)));
            CommonFunction.store32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (i + 2), (int)((((Z[j + 2] >>> 16) & ((1 << 8) - 1))) | (Z[j + 3] << 8)));

            j += Const.BYTE_SIZE / 2;

        }

        System.arraycopy(C, cOffset, signature, signatureOffset + Parameter.N_III_P * Parameter.D_III_P / Const.BYTE_SIZE, Polynomial.HASH);

    }

    /******************************************************************************************************************************
     * Description:	Decode Signature for Heuristic qTESLA Security Category-1 and Category-3 (Option for Size)
     *
     * @param    C
     * @param    Z
     * @param    signature            Output Package Containing Signature
     * @param    signatureOffset        Starting Point of the Output Package Containing Signature
     * @param    n                    Polynomial Degree
     * @param    d                    Number of Rounded Bits
     *
     * @return none
     ******************************************************************************************************************************/
    public static void decodeSignature(byte[] C, int[] Z, final byte[] signature, int signatureOffset, int n, int d)
    {

        int j = 0;

        for (int i = 0; i < n; i += Const.INT_SIZE)
        {

            Z[i + 0] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 0)) << 11) >> 11;

            Z[i + 1] = ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 0)) >>> 21) |
                (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 1)) << 22) >> 11);

            Z[i + 2] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 1)) << 1) >> 11;

            Z[i + 3] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 1)) >>> 31) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 2)) << 12) >> 11);

            Z[i + 4] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 2)) >>> 20) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 3)) << 23) >> 11);

            Z[i + 5] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 3)) << 2) >> 11;

            Z[i + 6] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 3)) >>> 30) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 4)) << 13) >> 11);

            Z[i + 7] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 4)) >>> 19) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 5)) << 24) >> 11);

            Z[i + 8] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 5)) << 3) >> 11;

            Z[i + 9] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 5)) >>> 29) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 6)) << 14) >> 11);

            Z[i + 10] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 6)) >>> 18) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 7)) << 25) >> 11);

            Z[i + 11] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 7)) << 4) >> 11;

            Z[i + 12] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 7)) >>> 28) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 8)) << 15) >> 11);

            Z[i + 13] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 8)) >>> 17) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 9)) << 26) >> 11);

            Z[i + 14] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 9)) << 5) >> 11;

            Z[i + 15] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 9)) >>> 27) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 10)) << 16) >> 11);

            Z[i + 16] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 10)) >>> 16) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 11)) << 27) >> 11);

            Z[i + 17] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 11)) << 6) >> 11;

            Z[i + 18] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 11)) >>> 26) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 12)) << 17) >> 11);

            Z[i + 19] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 12)) >>> 15) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 13)) << 28) >> 11);

            Z[i + 20] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 13)) << 7) >> 11;

            Z[i + 21] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 13)) >>> 25) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 14)) << 18) >> 11);

            Z[i + 22] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 14)) >>> 14) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 15)) << 29) >> 11);

            Z[i + 23] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 15)) << 8) >> 11;

            Z[i + 24] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 15)) >>> 24) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 16)) << 19) >> 11);

            Z[i + 25] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 16)) >>> 13) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 17)) << 30) >> 11);

            Z[i + 26] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 17)) << 9) >> 11;

            Z[i + 27] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 17)) >>> 23) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 18)) << 20) >> 11);

            Z[i + 28] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 18)) >>> 12) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 19)) << 31) >> 11);

            Z[i + 29] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 19)) << 10) >> 11;

            Z[i + 30] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 19)) >>> 22) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 20)) << 21) >> 11);

            Z[i + 31] = CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 20)) >> 11;

            j += d;

        }

        System.arraycopy(signature, signatureOffset + n * d / Const.BYTE_SIZE, C, 0, Polynomial.HASH);

    }

    /**************************************************************************************************************************************
     * Description:	Decode Signature for Heuristic qTESLA Security Category-3 (Option for Speed)
     *
     * @param    C
     * @param    Z
     * @param    signature            Output Package Containing Signature
     * @param    signatureOffset        Starting Point of the Output Package Containing Signature
     *
     * @return none
     **************************************************************************************************************************************/
    public static void decodeSignatureIIISpeed(byte[] C, int[] Z, final byte[] signature, int signatureOffset)
    {

        int j = 0;

        for (int i = 0; i < Parameter.N_III_SPEED; i += Const.INT_SIZE / 2)
        {

            Z[i + 0] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 0)) << 10) >> 10;

            Z[i + 1] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 0)) >>> 22) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 1)) << 20) >> 10);

            Z[i + 2] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 1)) >>> 12) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 2)) << 30) >> 10);

            Z[i + 3] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 2)) << 8) >> 10;

            Z[i + 4] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 2)) >>> 24) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 3)) << 18) >> 10);

            Z[i + 5] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 3)) >>> 14) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 4)) << 28) >> 10);

            Z[i + 6] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 4)) << 6) >> 10;

            Z[i + 7] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 4)) >>> 26) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 5)) << 16) >> 10);

            Z[i + 8] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 5)) >>> 16) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 6)) << 26) >> 10);

            Z[i + 9] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 6)) << 4) >> 10;

            Z[i + 10] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 6)) >>> 28) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 7)) << 14) >> 10);

            Z[i + 11] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 7)) >>> 18) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 8)) << 24) >> 10);

            Z[i + 12] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 8)) << 2) >> 10;

            Z[i + 13] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 8)) >>> 30) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 9)) << 12) >> 10);

            Z[i + 14] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 9)) >>> 20) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 10)) << 22) >> 10);

            Z[i + 15] = CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 10)) >> 10;

            j += Parameter.D_III_SPEED / 2;

        }

        System.arraycopy(signature, signatureOffset + Parameter.N_III_SPEED * Parameter.D_III_SPEED / Const.BYTE_SIZE, C, 0, Polynomial.HASH);

    }

    /****************************************************************************************************************************
     * Description:	Decode Signature for Provably-Secure qTESLA Security Category-1
     *
     * @param    C
     * @param    Z
     * @param    signature            Output Package Containing Signature
     * @param    signatureOffset        Starting Point of the Output Package Containing Signature
     *
     * @return none
     ****************************************************************************************************************************/
    public static void decodeSignatureIP(byte[] C, long[] Z, final byte[] signature, int signatureOffset)
    {

        int j = 0;

        for (int i = 0; i < Parameter.N_I_P; i += Const.INT_SIZE / 2)
        {

            Z[i + 0] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 0)) << 10) >> 10;

            Z[i + 1] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 0)) >>> 22) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 1)) << 20) >> 10);

            Z[i + 2] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 1)) >>> 12) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 2)) << 30) >> 10);

            Z[i + 3] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 2)) << 8) >> 10;

            Z[i + 4] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 2)) >>> 24) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 3)) << 18) >> 10);

            Z[i + 5] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 3)) >>> 14) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 4)) << 28) >> 10);

            Z[i + 6] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 4)) << 6) >> 10;

            Z[i + 7] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 4)) >>> 26) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 5)) << 16) >> 10);

            Z[i + 8] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 5)) >>> 16) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 6)) << 26) >> 10);

            Z[i + 9] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 6)) << 4) >> 10;

            Z[i + 10] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 6)) >>> 28) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 7)) << 14) >> 10);

            Z[i + 11] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 7)) >>> 18) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 8)) << 24) >> 10);

            Z[i + 12] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 8)) << 2) >> 10;

            Z[i + 13] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 8)) >>> 30) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 9)) << 12) >> 10);

            Z[i + 14] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 9)) >>> 20) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 10)) << 22) >> 10);

            Z[i + 15] = CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 10)) >> 10;

            j += Parameter.D_I_P / 2;

        }

        System.arraycopy(signature, signatureOffset + Parameter.N_I_P * Parameter.D_I_P / Const.BYTE_SIZE, C, 0, Polynomial.HASH);

    }

    /****************************************************************************************************************************************
     * Description:	Decode Signature for Provably-Secure qTESLA Security Category-3
     *
     * @param    C
     * @param    Z
     * @param    signature            Output Package Containing Signature
     * @param    signatureOffset        Starting Point of the Output Package Containing Signature
     *
     * @return none
     ****************************************************************************************************************************************/
    public static void decodeSignatureIIIP(byte[] C, long[] Z, final byte[] signature, int signatureOffset)
    {

        int j = 0;

        for (int i = 0; i < Parameter.N_III_P; i += Const.BYTE_SIZE / 2)
        {

            Z[i + 0] = (CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 0)) << 8) >> 8;

            Z[i + 1] = ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 0)) >>> 24) & ((1 << 8) - 1)) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 1)) << 16) >> 8);

            Z[i + 2] = ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 1)) >>> 16) & ((1 << 16) - 1)) |
                ((CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 2)) << 24) >> 8);

            Z[i + 3] = CommonFunction.load32(signature, signatureOffset + Const.INT_SIZE / Const.BYTE_SIZE * (j + 2)) >> 8;

            j += Const.BYTE_SIZE / 2 - 1;

        }

        System.arraycopy(signature, signatureOffset + Parameter.N_III_P * Parameter.D_III_P / Const.BYTE_SIZE, C, 0, Polynomial.HASH);

    }

}