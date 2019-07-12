package org.bouncycastle.pqc.crypto.qteslarnd1;

import java.security.SecureRandom;

public class QTESLA
{

    /******************************************************************************************************************************************
     * Description:	Hash Function to Generate C' for Heuristic qTESLA Security Category-1 and Category-3 (Option for Size or Speed)
     ******************************************************************************************************************************************/
    private static void hashFunction(byte[] output, int outputOffset, int[] V, final byte[] message, int messageOffset, int n, int d, int q)
    {

        int mask;
        int cL;

        byte[] T = new byte[n + Polynomial.MESSAGE];

        for (int i = 0; i < n; i++)
        {
            /* If V[i] > Q / 2 Then V[i] = V[i] - Q */
            mask = (q / 2 - V[i]) >> 31;
            V[i] = ((V[i] - q) & mask) | (V[i] & (~mask));
            cL = V[i] & ((1 << d) - 1);
            /* If cL > 2 ^ (d - 1) Then cL = cL - 2 ^ d */
            mask = ((1 << (d - 1)) - cL) >> 31;
            cL = ((cL - (1 << d)) & mask) | (cL & (~mask));
            T[i] = (byte)((V[i] - cL) >> d);

        }

        System.arraycopy(message, messageOffset, T, n, Polynomial.MESSAGE);

        if (q == Parameter.Q_I)
        {

            HashUtils.secureHashAlgorithmKECCAK128(output, outputOffset, Polynomial.HASH, T, 0, n + Polynomial.MESSAGE);

        }

        if (q == Parameter.Q_III_SIZE || q == Parameter.Q_III_SPEED)
        {

            HashUtils.secureHashAlgorithmKECCAK256(output, outputOffset, Polynomial.HASH, T, 0, n + Polynomial.MESSAGE);

        }

    }

    /**************************************************************************************************************************************************
     * Description:	Hash Function to Generate C' for Provably-Secure qTESLA Security Category-1 and Security Category-3
     **************************************************************************************************************************************************/
    private static void hashFunction(byte[] output, int outputOffset, long[] V, final byte[] message, int messageOffset, int n, int k, int d, int q)
    {

        int index;
        long mask;
        long cL;
        long temporary;

        byte[] T = new byte[n * k + Polynomial.MESSAGE];

        for (int j = 0; j < k; j++)
        {

            index = n * j;

            for (int i = 0; i < n; i++)
            {

                temporary = V[index];
                /* If V[i] > Q / 2 Then V[i] = V[i] - Q */
                mask = (q / 2 - temporary) >> 63;
                temporary = ((temporary - q) & mask) | (temporary & (~mask));
                cL = temporary & ((1 << d) - 1);
                /* If cL > 2 ^ (d - 1) Then cL = cL - 2 ^ d */
                mask = ((1 << (d - 1)) - cL) >> 63;
                cL = ((cL - (1 << d)) & mask) | (cL & (~mask));
                T[index++] = (byte)((temporary - cL) >> d);

            }

        }

        System.arraycopy(message, messageOffset, T, n * k, Polynomial.MESSAGE);

        if (q == Parameter.Q_I_P)
        {

            HashUtils.secureHashAlgorithmKECCAK128(output, outputOffset, Polynomial.HASH, T, 0, n * k + Polynomial.MESSAGE);

        }

        if (q == Parameter.Q_III_P)
        {

            HashUtils.secureHashAlgorithmKECCAK256(output, outputOffset, Polynomial.HASH, T, 0, n * k + Polynomial.MESSAGE);

        }

    }

    /**************************************************************************************************************************************
     * Description:	Computes Absolute Value for for Heuristic qTESLA Security Category-1 and Security Category-3 (Option for Size or Speed)
     **************************************************************************************************************************************/
    private static int absolute(int value)
    {

        return ((value >> 31) ^ value) - (value >> 31);

    }

    /*****************************************************************************************************************
     * Description:	Computes Absolute Value for for Provably-Secure qTESLA Security Category-1 and Security Category-3
     *****************************************************************************************************************/
    private static long absolute(long value)
    {

        return ((value >> 63) ^ value) - (value >> 63);

    }

    /*********************************************************************************
     * Description:	Checks Bounds for Signature Vector Z During Signification.
     * 				Leaks the Position of the Coefficient that Fails the Test.
     * 				The Position of the Coefficient is Independent of the Secret Data.
     * 				Does not Leak the Signature of the Coefficients.
     * 				For Heuristic qTESLA Security Category-1 and Security Category-3
     * 				(Option for Size or Speed)
     *
     * @param        Z        Signature Vector
     * @param        n        Polynomial Degree
     * @param        b        Interval the Randomness is Chosen in During Signification
     * @param        u        Bound in Checking Secret Polynomial
     *
     * @return false    Valid / Accepted
     * 				true	Invalid / Rejected
     ********************************************************************************/
    private static boolean testRejection(int[] Z, int n, int b, int u)
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

    /*************************************************************************************
     * Description:	Checks Bounds for Signature Vector Z During Signification.
     * 				Leaks the Position of the Coefficient that Fails the Test.
     * 				The Position of the Coefficient is Independent of the Secret Data.
     * 				Does not Leak the Signature of the Coefficients.
     * 				For Provably-Secure qTESLA Security Category-1 and Security Category-3
     *
     * @param        Z        Signature Vector
     * @param        n        Polynomial Degree
     * @param        b        Interval the Randomness is Chosen in During Signification
     * @param        u        Bound in Checking Secret Polynomial
     *
     * @return false    Valid / Accepted
     * 				true	Invalid / Rejected
     *************************************************************************************/
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
     * 				for Heuristic qTESLA Security Category-1 and Security Category-3
     * 				(Option of Size of Speed)
     *
     * @param        Z        Signature Vector
     * @param        n        Polynomial Degree
     * @param        b        Interval the Randomness is Chosen in During Signification
     * @param        u        Bound in Checking Secret Polynomial
     *
     * @return false    Valid / Accepted
     * 				true	Invalid / Rejected
     *********************************************************************************/
    private static boolean testZ(int[] Z, int n, int b, int u)
    {

        for (int i = 0; i < n; i++)
        {

            if ((Z[i] < -(b - u)) || (Z[i] > b - u))
            {

                return true;

            }

        }

        return false;

    }

    /*************************************************************************************
     * Description:	Checks Bounds for Signature Vector Z During Signature Verification
     * 				for Provably-Secure qTESLA Security Category-1 and Security Category-3
     *
     * @param        Z        Signature Vector
     * @param        n        Polynomial Degree
     * @param        b        Interval the Randomness is Chosen in During Signification
     * @param        u        Bound in Checking Secret Polynomial
     *
     * @return false    Valid / Accepted
     * 				true	Invalid / Rejected
     *************************************************************************************/
    private static boolean testZ(long[] Z, int n, int b, int u)
    {

        for (int i = 0; i < n; i++)
        {

            if ((Z[i] < -(b - u)) || (Z[i] > b - u))
            {

                return true;

            }

        }

        return false;

    }

    /*********************************************************************************
     * Description:	Checks Bounds for W = V - EC During Signature Verification.
     * 				Leaks the Position of the Coefficient that Fails the Test.
     * 				The Position of the Coefficient is Independent of the Secret Data.
     * 				Does not Leak the Signature of the Coefficients.
     * 				For Heuristic qTESLA Security Category-1 and Security Category-3
     * 				(Option for Size or Speed)
     *
     * @param        V            Parameter to be Checked
     * @param        n            Polynomial Degree
     * @param        d            Number of Rounded Bits
     * @param        q            Modulus
     * @param        rejection    Bound in Checking Error Polynomial
     *
     * @return false        Valid / Accepted
     * 				true		Invalid / Rejected
     *********************************************************************************/
    private static boolean testV(int[] V, int n, int d, int q, int rejection)
    {

        int mask;
        int left;
        int right;
        int test1;
        int test2;

        for (int i = 0; i < n; i++)
        {

            mask = (q / 2 - V[i]) >> 31;
            right = ((V[i] - q) & mask) | (V[i] & (~mask));
            test1 = (~(absolute(right) - (q / 2 - rejection))) >>> 31;
            left = right;
            right = (right + (1 << (d - 1)) - 1) >> d;
            right = left - (right << d);
            test2 = (~(absolute(right) - ((1 << (d - 1)) - rejection))) >>> 31;

            /* Two Tests Fail */
            if ((test1 | test2) == 1)
            {

                return true;

            }

        }

        return false;

    }

    /****************************************************************************************
     * Description:	Checks Bounds for W = V - EC During Signature Verification.
     * 				Leaks the Position of the Coefficient that Fails the Test.
     * 				The Position of the Coefficient is Independent of the Secret Data.
     * 				Does not Leak the Signature of the Coefficients.
     * 				For Provably-Secure qTESLA Security Category-1 and Security Category-3
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
     ****************************************************************************************/
    private static boolean testV(long[] V, int vOffset, int n, int d, int q, int rejection)
    {

        long mask;
        long left;
        long right;
        long test1;
        long test2;

        for (int i = 0; i < n; i++)
        {

            mask = (q / 2 - V[vOffset + i]) >> 63;
            right = ((V[vOffset + i] - q) & mask) | (V[vOffset + i] & (~mask));
            test1 = (~(absolute(right) - (q / 2 - rejection))) >>> 63;

            left = right;
            right = (int)((right + (1 << (d - 1)) - 1) >> d);
            right = left - (right << d);
            test2 = (~(absolute(right) - ((1 << (d - 1)) - rejection))) >>> 63;

            /* Two Tests Fail */
            if ((test1 | test2) == 1L)
            {

                return true;

            }

        }

        return false;

    }

    /**********************************************************************************************************
     * Description:	Checks Whether the Generated Error Polynomial or the Generated Secret Polynomial
     *				Fulfills Certain Properties Needed in Key Generation Algorithm
     *				For Heuristic qTESLA Security Category-1 and Security Category-3 (Option for Size or Speed)
     *
     * @param        polynomial        Parameter to be Checked
     * @param        bound            Threshold of Summation
     * @param        n                Polynomial Degree
     * @param        h                Number of Non-Zero Entries of Output Elements of Encryption
     *
     * @return false            Fulfillment
     * 				true			No Fulfillment
     **********************************************************************************************************/
    private static boolean checkPolynomial(int[] polynomial, int bound, int n, int h)
    {

        int summation = 0;
        int limit = n;
        int temporary;
        int mask;
        int[] list = new int[n];

        for (int i = 0; i < n; i++)
        {

            list[i] = absolute(polynomial[i]);

        }

        for (int i = 0; i < h; i++)
        {

            for (int j = 0; j < limit - 1; j++)
            {
                /* If list[j + 1] > list[j] Then Exchanges Contents */
                mask = (list[j + 1] - list[j]) >> 31;
                temporary = (list[j + 1] & mask) | (list[j] & (~mask));
                list[j + 1] = (list[j] & mask) | (list[j + 1] & (~mask));
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

    /**********************************************************************************************************
     * Description:	Checks Whether the Generated Error Polynomial or the Generated Secret Polynomial
     *				Fulfills Certain Properties Needed in Key Generation Algorithm
     *				For Provably-Secure qTESLA Security Category-1 and Security Category-3
     *
     * @param        polynomial        Parameter to be Checked
     * @param        offset            Starting Point of the Polynomial to be Checked
     * @param        bound            Threshold of Summation
     * @param        n                Polynomial Degree
     * @param        h                Number of Non-Zero Entries of Output Elements of Encryption
     *
     * @return false            Fulfillment
     * 				true			No Fulfillment
     **********************************************************************************************************/
    private static boolean checkPolynomial(long[] polynomial, int offset, int bound, int n, int h)
    {

        int summation = 0;
        int limit = n;
        short temporary;
        short mask;
        short[] list = new short[n];

        for (int i = 0; i < n; i++)
        {

            list[i] = (short)(absolute(polynomial[offset + i]));

        }

        for (int i = 0; i < h; i++)
        {

            for (int j = 0; j < limit - 1; j++)
            {
                /* If list[j + 1] > list[j] Then Exchanges Contents */
                mask = (short)((list[j + 1] - list[j]) >> 15);
                temporary = (short)((list[j + 1] & mask) | (list[j] & (~mask)));
                list[j + 1] = (short)((list[j] & mask) | (list[j + 1] & (~mask)));
                list[j] = temporary;

            }

            summation += (int)list[limit - 1];
            limit--;

        }

        if (summation > bound)
        {

            return true;

        }

        return false;

    }

    /************************************************************************************************************************************************************
     * Description:	Generates A Pair of Public Key and Private Key for qTESLA Signature Scheme for Heuristic qTESLA Security Category-1 and Security Category-3
     *				(Option for Size or Speed)
     *
     * @param        publicKey                            Contains Public Key
     * @param        privateKey                            Contains Private Key
     * @param        secureRandom                        Source of Randomness
     * @param        n                                    Polynomial Degree
     * @param        h                                    Number of Non-Zero Entries of Output Elements of Encryption
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
     ************************************************************************************************************************************************************/
    private static int generateKeyPair(

        byte[] publicKey, byte[] privateKey, SecureRandom secureRandom,
        int n, int h, int q, long qInverse, int qLogarithm, int generatorA, int inverseNumberTheoreticTransform, double xi,
        int[] zeta,
        int errorBound, int secretBound)
    {

        /* Initialize Domain Separator for Error Polynomial and Secret Polynomial */
        int nonce = 0;

        byte[] randomness = new byte[Polynomial.RANDOM];

        /* Extend Random Bytes to Seed Generation of Error Polynomial and Secret Polynomial */
        byte[] randomnessExtended = new byte[Polynomial.SEED * 4];

        int[] secretPolynomial = new int[n];
        int[] errorPolynomial = new int[n];
        int[] A = new int[n];
        int[] T = new int[n];

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

                Sample.polynomialGaussSamplerI(errorPolynomial, 0, randomnessExtended, 0, ++nonce);

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
        while (checkPolynomial(errorPolynomial, errorBound, n, h) == true);

        /*
         * Sample the Secret Polynomial Fulfilling the Criteria
         * Choose Secret Polynomial in R with Entries from D_SIGMA
         * Repeat Step if the h Largest Entries of Secret Polynomial Summation to L_S
         */
        do
        {

            if (q == Parameter.Q_I)
            {

                Sample.polynomialGaussSamplerI(secretPolynomial, 0, randomnessExtended, Polynomial.SEED, ++nonce);

            }

            if (q == Parameter.Q_III_SIZE)
            {

                Sample.polynomialGaussSamplerIII(secretPolynomial, 0, randomnessExtended, Polynomial.SEED, ++nonce, n, xi, Sample.EXPONENTIAL_DISTRIBUTION_III_SIZE);

            }

            if (q == Parameter.Q_III_SPEED)
            {

                Sample.polynomialGaussSamplerIII(secretPolynomial, 0, randomnessExtended, Polynomial.SEED, ++nonce, n, xi, Sample.EXPONENTIAL_DISTRIBUTION_III_SPEED);

            }

        }
        while (checkPolynomial(secretPolynomial, secretBound, n, h) == true);

        /* Generate Uniform Polynomial A */
        Polynomial.polynomialUniform(A, randomnessExtended, Polynomial.SEED * 2, n, q, qInverse, qLogarithm, generatorA, inverseNumberTheoreticTransform);

        /* Compute the Public Key T = A * secretPolynomial + errorPolynomial */
        Polynomial.polynomialMultiplication(T, A, secretPolynomial, n, q, qInverse, zeta);
        Polynomial.polynomialAdditionCorrection(T, T, errorPolynomial, n, q);

        /* Pack Public and Private Keys */
        if (q == Parameter.Q_I)
        {

            Pack.encodePrivateKeyI(privateKey, secretPolynomial, errorPolynomial, randomnessExtended, Polynomial.SEED * 2);
            Pack.encodePublicKey(publicKey, T, randomnessExtended, Polynomial.SEED * 2, Parameter.N_I, Parameter.Q_LOGARITHM_I);

        }

        if (q == Parameter.Q_III_SIZE)
        {

            Pack.encodePrivateKeyIIISize(privateKey, secretPolynomial, errorPolynomial, randomnessExtended, Polynomial.SEED * 2);
            Pack.encodePublicKey(publicKey, T, randomnessExtended, Polynomial.SEED * 2, Parameter.N_III_SIZE, Parameter.Q_LOGARITHM_III_SIZE);

        }

        if (q == Parameter.Q_III_SPEED)
        {

            Pack.encodePrivateKeyIIISpeed(privateKey, secretPolynomial, errorPolynomial, randomnessExtended, Polynomial.SEED * 2);
            Pack.encodePublicKeyIIISpeed(publicKey, T, randomnessExtended, Polynomial.SEED * 2);

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
    public static int generateKeyPairI(byte[] publicKey, byte[] privateKey, SecureRandom secureRandom)
    {

        return generateKeyPair(

            publicKey, privateKey, secureRandom,
            Parameter.N_I, Parameter.H_I, Parameter.Q_I, Parameter.Q_INVERSE_I, Parameter.Q_LOGARITHM_I,
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
     ****************************************************************************************************************************************************************/
    public static int generateKeyPairIIISize(byte[] publicKey, byte[] privateKey, SecureRandom secureRandom)
    {

        return generateKeyPair(

            publicKey, privateKey, secureRandom,
            Parameter.N_III_SIZE, Parameter.H_III_SIZE, Parameter.Q_III_SIZE, Parameter.Q_INVERSE_III_SIZE, Parameter.Q_LOGARITHM_III_SIZE,
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
    public static int generateKeyPairIIISpeed(byte[] publicKey, byte[] privateKey, SecureRandom secureRandom)
    {

        return generateKeyPair(

            publicKey, privateKey, secureRandom,
            Parameter.N_III_SPEED, Parameter.H_III_SPEED, Parameter.Q_III_SPEED, Parameter.Q_INVERSE_III_SPEED, Parameter.Q_LOGARITHM_III_SPEED,
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
     * @param        h                                    Number of Non-Zero Entries of Output Elements of Encryption
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
        int n, int k, int h, int q, long qInverse, int qLogarithm, int generatorA, int inverseNumberTheoreticTransform, double xi,
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
//        rng.randomByte(randomness, 0, Polynomial.RANDOM);
        secureRandom.nextBytes (randomness);

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

                    Sample.polynomialGaussSamplerIP(errorPolynomial, n * i, randomnessExtended, Polynomial.SEED * i, ++nonce);

                }

                if (q == Parameter.Q_III_P)
                {

                    Sample.polynomialGaussSamplerIIIP(errorPolynomial, n * i, randomnessExtended, Polynomial.SEED * i, ++nonce);

                }

            }
            while (checkPolynomial(errorPolynomial, n * i, errorBound, n, h) == true);

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

                Sample.polynomialGaussSamplerIP(secretPolynomial, 0, randomnessExtended, Polynomial.SEED * k, ++nonce);

            }

            if (q == Parameter.Q_III_P)
            {

                Sample.polynomialGaussSamplerIIIP(secretPolynomial, 0, randomnessExtended, Polynomial.SEED * k, ++nonce);

            }

        }
        while (checkPolynomial(secretPolynomial, 0, secretBound, n, h) == true);

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
        Pack.packPrivateKey(privateKey, secretPolynomial, errorPolynomial, randomnessExtended, Polynomial.SEED * (k + 1), n, k);

        if (q == Parameter.Q_I_P)
        {

            Pack.encodePublicKeyIP(publicKey, T, randomnessExtended, Polynomial.SEED * (k + 1));

        }

        if (q == Parameter.Q_III_P)
        {

            Pack.encodePublicKeyIIIP(publicKey, T, randomnessExtended, Polynomial.SEED * (k + 1));

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
    public static int generateKeyPairIP(byte[] publicKey, byte[] privateKey, SecureRandom secureRandom)
    {

        return generateKeyPair(

            publicKey, privateKey, secureRandom,
            Parameter.N_I_P, Parameter.K_I_P, Parameter.H_I_P, Parameter.Q_I_P, Parameter.Q_INVERSE_I_P, Parameter.Q_LOGARITHM_I_P,
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
    public static int generateKeyPairIIIP(byte[] publicKey, byte[] privateKey, SecureRandom secureRandom)
    {

        return generateKeyPair(

            publicKey, privateKey, secureRandom,
            Parameter.N_III_P, Parameter.K_III_P, Parameter.H_III_P, Parameter.Q_III_P, Parameter.Q_INVERSE_III_P, Parameter.Q_LOGARITHM_III_P,
            Parameter.GENERATOR_A_III_P, Parameter.INVERSE_NUMBER_THEORETIC_TRANSFORM_III_P,
            Parameter.XI_III_P,
            PolynomialProvablySecure.ZETA_III_P,
            Parameter.KEY_GENERATOR_BOUND_E_III_P, Parameter.KEY_GENERATOR_BOUND_S_III_P

        );

    }

    /******************************************************************************************************************************************************
     * Description:	Generates A Signature for A Given Message According to the Ring-TESLA Signature Scheme for Heuristic qTESLA Security Category-1 and
     * 				Security Category-3 (Option for Size or Speed)
     *
     * @param        message                                Message to be Signed
     * @param        messageOffset                        Starting Point of the Message to be Signed
     * @param        messageLength                        Length of the Message to be Signed
     * @param        signature                            Output Package Containing Signature
     * @param        privateKey                            Private Key
     * @param        secureRandom                        Source of Randomness
     * @param        n                                    Polynomial Degree
     * @param        h                                    Number of Non-Zero Entries of Output Elements of Encryption
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
        int n, int h, int q, long qInverse, int qLogarithm, int b, int bBit, int d, int u, int rejection,
        int generatorA, int inverseNumberTheoreticTransform,
        int barrettMultiplication, int barrettDivision,
        int[] zeta

    )
    {

        byte[] C = new byte[Polynomial.HASH];
        byte[] randomness = new byte[Polynomial.SEED];
        byte[] randomnessInput = new byte[Polynomial.RANDOM + Polynomial.SEED + Polynomial.MESSAGE];
        byte[] seed = new byte[Polynomial.SEED * 2];
        byte[] temporaryRandomnessInput	= new byte[Polynomial.RANDOM];
        int[] positionList = new int[h];
        short[] signList = new short[h];
        short[] secretPolynomial = new short[n];
        short[] errorPolynomial = new short[n];

        int[] A = new int[n];
        int[] V = new int[n];
        int[] Y = new int[n];
        int[] Z = new int[n];
        int[] SC = new int[n];
        int[] EC = new int[n];

        /* Domain Separator for Sampling Y */
        int nonce = 0;

        if (q == Parameter.Q_I)
        {

            Pack.decodePrivateKeyI(seed, secretPolynomial, errorPolynomial, privateKey);

        }

        if (q == Parameter.Q_III_SIZE)
        {

            Pack.decodePrivateKeyIIISize(seed, secretPolynomial, errorPolynomial, privateKey);

        }

        if (q == Parameter.Q_III_SPEED)
        {

            Pack.decodePrivateKeyIIISpeed(seed, secretPolynomial, errorPolynomial, privateKey);

        }

//        rng.randomByte(randomnessInput, Polynomial.RANDOM, Polynomial.RANDOM);
         secureRandom.nextBytes (temporaryRandomnessInput);
         System.arraycopy (temporaryRandomnessInput, 0, randomnessInput, Polynomial.RANDOM, Polynomial.RANDOM);

        System.arraycopy(seed, Polynomial.SEED, randomnessInput, 0, Polynomial.SEED);

        if (q == Parameter.Q_I)
        {

            HashUtils.secureHashAlgorithmKECCAK128(
                randomnessInput, Polynomial.RANDOM + Polynomial.SEED, Polynomial.MESSAGE, message, 0, messageLength
            );

            HashUtils.secureHashAlgorithmKECCAK128(
                randomness, 0, Polynomial.SEED, randomnessInput, 0, Polynomial.RANDOM + Polynomial.SEED + Polynomial.MESSAGE
            );

        }

        if (q == Parameter.Q_III_SIZE || q == Parameter.Q_III_SPEED)
        {

            HashUtils.secureHashAlgorithmKECCAK256(
                randomnessInput, Polynomial.RANDOM + Polynomial.SEED, Polynomial.MESSAGE, message, 0, messageLength
            );

            HashUtils.secureHashAlgorithmKECCAK256(
                randomness, 0, Polynomial.SEED, randomnessInput, 0, Polynomial.RANDOM + Polynomial.SEED + Polynomial.MESSAGE
            );

        }

        Polynomial.polynomialUniform(A, seed, 0, n, q, qInverse, qLogarithm, generatorA, inverseNumberTheoreticTransform);

        /* Loop Due to Possible Rejection */
        while (true)
        {

            /* Sample Y Uniformly Random from -B to B */
            Sample.sampleY(Y, randomness, 0, ++nonce, n, q, b, bBit);

            /* V = A * Y Modulo Q */
            Polynomial.polynomialMultiplication(V, A, Y, n, q, qInverse, zeta);

            hashFunction(C, 0, V, randomnessInput, Polynomial.RANDOM + Polynomial.SEED, n, d, q);

            /* Generate C = EncodeC (C') Where C' is the Hashing of V Together with Message */
            Sample.encodeC(positionList, signList, C, 0, n, h);

            Polynomial.sparsePolynomialMultiplication16(SC, secretPolynomial, positionList, signList, n, h);

            /* Z = Y + EC Modulo Q */
            Polynomial.polynomialAddition(Z, Y, SC, n);

            /* Rejection Sampling */
            if (testRejection(Z, n, b, u) == true)
            {

                continue;

            }

            Polynomial.sparsePolynomialMultiplication16(EC, errorPolynomial, positionList, signList, n, h);

            /* V = V - EC modulo Q */
            Polynomial.polynomialSubtractionCorrection(V, V, EC, n, q);

            if (testV(V, n, d, q, rejection) == true)
            {
                continue;
            }

            if (q == Parameter.Q_I)
            {
                /* Pack Signature */
                Pack.encodeSignature(signature, 0, C, 0, Z, n, d);
            }

            if (q == Parameter.Q_III_SIZE)
            {
                /* Pack Signature */
                Pack.encodeSignature(signature, 0, C, 0, Z, n, d);
            }

            if (q == Parameter.Q_III_SPEED)
            {
                /* Pack Signature */
                Pack.encodeSignatureIIISpeed(signature, 0, C, 0, Z);
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
            Parameter.N_I, Parameter.H_I, Parameter.Q_I, Parameter.Q_INVERSE_I, Parameter.Q_LOGARITHM_I,
            Parameter.B_I, Parameter.B_BIT_I, Parameter.D_I, Parameter.U_I, Parameter.REJECTION_I,
            Parameter.GENERATOR_A_I, Parameter.INVERSE_NUMBER_THEORETIC_TRANSFORM_I,
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
            Parameter.N_III_SIZE, Parameter.H_III_SIZE, Parameter.Q_III_SIZE, Parameter.Q_INVERSE_III_SIZE, Parameter.Q_LOGARITHM_III_SIZE,
            Parameter.B_III_SIZE, Parameter.B_BIT_III_SIZE, Parameter.D_III_SIZE, Parameter.U_III_SIZE, Parameter.REJECTION_III_SIZE,
            Parameter.GENERATOR_A_III_SIZE, Parameter.INVERSE_NUMBER_THEORETIC_TRANSFORM_III_SIZE,
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
            Parameter.N_III_SPEED, Parameter.H_III_SPEED, Parameter.Q_III_SPEED, Parameter.Q_INVERSE_III_SPEED, Parameter.Q_LOGARITHM_III_SPEED,
            Parameter.B_III_SPEED, Parameter.B_BIT_III_SPEED, Parameter.D_III_SPEED, Parameter.U_III_SPEED, Parameter.REJECTION_III_SPEED,
            Parameter.GENERATOR_A_III_SPEED, Parameter.INVERSE_NUMBER_THEORETIC_TRANSFORM_III_SPEED,
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
     * @param        h                                    Number of Non-Zero Entries of Output Elements of Encryption
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
        int n, int k, int h, int q, long qInverse, int qLogarithm, int b, int bBit, int d, int u, int rejection,
        int generatorA, int inverseNumberTheoreticTransform, int privateKeySize,
        int barrettMultiplication, int barrettDivision

    )
    {

        byte[] C = new byte[Polynomial.HASH];
        byte[] randomness = new byte[Polynomial.SEED];
        byte[] randomnessInput = new byte[Polynomial.RANDOM + Polynomial.SEED + Polynomial.MESSAGE];
        byte[] temporaryRandomnessInput	= new byte[Polynomial.RANDOM];
        int[] positionList = new int[h];
        short[] signList = new short[h];

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

//        rng.randomByte(randomnessInput, Polynomial.RANDOM, Polynomial.RANDOM);
        secureRandom.nextBytes (temporaryRandomnessInput);
        System.arraycopy (temporaryRandomnessInput, 0, randomnessInput, Polynomial.RANDOM, Polynomial.RANDOM);
        System.arraycopy(privateKey, privateKeySize - Polynomial.SEED, randomnessInput, 0, Polynomial.SEED);

        if (q == Parameter.Q_I_P)
        {

            HashUtils.secureHashAlgorithmKECCAK128(
                randomnessInput, Polynomial.RANDOM + Polynomial.SEED, Polynomial.MESSAGE, message, 0, messageLength
            );


            HashUtils.secureHashAlgorithmKECCAK128(
                randomness, 0, Polynomial.SEED, randomnessInput, 0, Polynomial.RANDOM + Polynomial.SEED + Polynomial.MESSAGE
            );

        }

        if (q == Parameter.Q_III_P)
        {

            HashUtils.secureHashAlgorithmKECCAK256(
                randomnessInput, Polynomial.RANDOM + Polynomial.SEED, Polynomial.MESSAGE, message, 0, messageLength
            );


            HashUtils.secureHashAlgorithmKECCAK256(
                randomness, 0, Polynomial.SEED, randomnessInput, 0, Polynomial.RANDOM + Polynomial.SEED + Polynomial.MESSAGE
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
            for (int i = 0; i < k; i++)
            {

                Polynomial.polynomialMultiplication(V, n * i, A, n * i, numberTheoreticTransformY, 0, n, q, qInverse);

            }

            hashFunction(C, 0, V, randomnessInput, Polynomial.RANDOM + Polynomial.SEED, n, k, d, q);

            /* Generate C = EncodeC (C') Where C' is the Hashing of V Together with Message */
            Sample.encodeC(positionList, signList, C, 0, n, h);

            Polynomial.sparsePolynomialMultiplication8(SC, 0, privateKey, 0, positionList, signList, n, h);

            /* Z = Y + EC modulo Q */
            Polynomial.polynomialAddition(Z, 0, Y, 0, SC, 0, n);

            /* Rejection Sampling */
            if (testRejection(Z, n, b, u) == true)
            {

                continue;

            }

            for (int i = 0; i < k; i++)
            {

                Polynomial.sparsePolynomialMultiplication8(EC, n * i, privateKey, n * (i + 1), positionList, signList, n, h);

                /* V_i = V_i - EC_i Modulo Q for All k */
                Polynomial.polynomialSubtraction(V, n * i, V, n * i, EC, n * i, n, q, barrettMultiplication, barrettDivision);

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
                Pack.encodeSignatureIP(signature, 0, C, 0, Z);

            }

            if (q == Parameter.Q_III_P)
            {
                /* Pack Signature */
                Pack.encodeSignatureIIIP(signature, 0, C, 0, Z);
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
    public static int signingIP(

        byte[] signature,
        final byte[] message, int messageOffset, int messageLength,
        final byte[] privateKey, SecureRandom secureRandom

    )
    {

        return signing(

            signature,
            message, messageOffset, messageLength,
            privateKey, secureRandom,
            Parameter.N_I_P, Parameter.K_I_P, Parameter.H_I_P, Parameter.Q_I_P, Parameter.Q_INVERSE_I_P, Parameter.Q_LOGARITHM_I_P,
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
    public static int signingIIIP(

        byte[] signature,
        final byte[] message, int messageOffset, int messageLength,
        final byte[] privateKey, SecureRandom secureRandom

    )
    {

        return signing(

            signature,
            message, messageOffset, messageLength,
            privateKey, secureRandom,
            Parameter.N_III_P, Parameter.K_III_P, Parameter.H_III_P, Parameter.Q_III_P, Parameter.Q_INVERSE_III_P, Parameter.Q_LOGARITHM_III_P,
            Parameter.B_III_P, Parameter.B_BIT_III_P, Parameter.D_III_P, Parameter.U_III_P, Parameter.REJECTION_III_P,
            Parameter.GENERATOR_A_III_P, Parameter.INVERSE_NUMBER_THEORETIC_TRANSFORM_III_P, Polynomial.PRIVATE_KEY_III_P,
            Parameter.BARRETT_MULTIPLICATION_III_P, Parameter.BARRETT_DIVISION_III_P

        );

    }

    /*********************************************************************************************************************************
     * Description:	Extracts the Original Message and Checks Whether the Generated Signature is Valid for A Given Signature Package
     * 				for Heuristic qTESLA Security Category-1 and Security Category-3 (Option for Size of Speed)
     *
     * @param        signature                            Given Signature Package
     * @param        signatureOffset                        Starting Point of the Given Signature Package
     * @param        signatureLength                        Length of the Given Signature Package
     * @param        message                                Original (Signed) Message
     * @param        publicKey                            Public Key
     * @param        n                                    Polynomial Degree
     * @param        h                                    Number of Non-Zero Entries of Output Elements of Encryption
     * @param        q                                    Modulus
     * @param        qInverse
     * @param        qLogarithm                            q <= 2 ^ qLogarithm
     * @param        b                                    Determines the Interval the Randomness is Chosen in During Signing
     * @param        d                                    Number of Rounded Bits
     * @param        u                                    Bound in Checking Secret Polynomial
     * @param        r
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
        int n, int h, int q, long qInverse, int qLogarithm, int b, int d, int u, int r, int signatureSize,
        int generatorA, int inverseNumberTheoreticTransform,
        int barrettMultiplication, int barrettDivision,
        int[] zeta

    )
    {

        byte[] C = new byte[Polynomial.HASH];
        byte[] cSignature = new byte[Polynomial.HASH];
        byte[] seed = new byte[Polynomial.SEED];
        byte[] hashMessage = new byte[Polynomial.MESSAGE];
        int[] newPublicKey = new int[n];

        int[] positionList = new int[h];
        short[] signList = new short[h];

        int[] W = new int[n];
        int[] Z = new int[n];
        int[] TC = new int[n];
        int[] A = new int[n];

        if (signatureLength < signatureSize)
        {

            return -1;

        }

        if (q == Parameter.Q_I || q == Parameter.Q_III_SIZE)
        {

            Pack.decodeSignature(C, Z, signature, signatureOffset, n, d);

        }

        if (q == Parameter.Q_III_SPEED)
        {

            Pack.decodeSignatureIIISpeed(C, Z, signature, signatureOffset);

        }

        /* Check Norm of Z */
        if (testZ(Z, n, b, u) == true)
        {

            return -2;

        }

        if (q == Parameter.Q_I || q == Parameter.Q_III_SIZE)
        {

            Pack.decodePublicKey(newPublicKey, seed, 0, publicKey, n, qLogarithm);

        }

        if (q == Parameter.Q_III_SPEED)
        {

            Pack.decodePublicKeyIIISpeed(newPublicKey, seed, 0, publicKey);

        }

        /* Generate A Polynomial */
        Polynomial.polynomialUniform(A, seed, 0, n, q, qInverse, qLogarithm, generatorA, inverseNumberTheoreticTransform);

        Sample.encodeC(positionList, signList, C, 0, n, h);

        /* W = A * Z - TC */
        Polynomial.sparsePolynomialMultiplication32(TC, newPublicKey, positionList, signList, n, h);

        Polynomial.polynomialMultiplication(W, A, Z, n, q, qInverse, zeta);

        Polynomial.polynomialSubtractionMontgomery(W, W, TC, n, q, qInverse, r);

        if (q == Parameter.Q_I)
        {

            HashUtils.secureHashAlgorithmKECCAK128(
                hashMessage, 0, Polynomial.MESSAGE, message, 0, message.length
            );

        }

        if (q == Parameter.Q_III_SIZE || q == Parameter.Q_III_SPEED)
        {

            HashUtils.secureHashAlgorithmKECCAK256(
                hashMessage, 0, Polynomial.MESSAGE, message, 0, message.length
            );

        }

        /* Obtain the Hash Symbol */
        hashFunction(cSignature, 0, W, hashMessage, 0, n, d, q);

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
            Parameter.N_I, Parameter.H_I, Parameter.Q_I, Parameter.Q_INVERSE_I, Parameter.Q_LOGARITHM_I,
            Parameter.B_I, Parameter.D_I, Parameter.U_I, Parameter.R_I,
            Polynomial.SIGNATURE_I,
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
            Parameter.N_III_SIZE, Parameter.H_III_SIZE,
            Parameter.Q_III_SIZE, Parameter.Q_INVERSE_III_SIZE, Parameter.Q_LOGARITHM_III_SIZE,
            Parameter.B_III_SIZE, Parameter.D_III_SIZE, Parameter.U_III_SIZE, Parameter.R_III_SIZE,
            Polynomial.SIGNATURE_III_SIZE,
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
            Parameter.N_III_SPEED, Parameter.H_III_SPEED,
            Parameter.Q_III_SPEED, Parameter.Q_INVERSE_III_SPEED, Parameter.Q_LOGARITHM_III_SPEED,
            Parameter.B_III_SPEED, Parameter.D_III_SPEED, Parameter.U_III_SPEED, Parameter.R_III_SPEED,
            Polynomial.SIGNATURE_III_SPEED,
            Parameter.GENERATOR_A_III_SPEED, Parameter.INVERSE_NUMBER_THEORETIC_TRANSFORM_III_SPEED,
            Parameter.BARRETT_MULTIPLICATION_III_SPEED, Parameter.BARRETT_DIVISION_III_SPEED,
            PolynomialHeuristic.ZETA_III_SPEED

        );

    }

    /**************************************************************************************************************************
     * Description:	Extracts the Original Message and Checks Whether the Generated Signature is Valid for A Given Signature
     * 				Package for Provably-Secure qTESLA Security Category-1 and Category-3
     *
     * @param        signature                            Given Signature Package
     * @param        signatureOffset                        Starting Point of the Given Signature Package
     * @param        signatureLength                        Length of the Given Signature Package
     * @param        message                                Original (Signed) Message
     * @param        publicKey                            Public Key
     * @param        n                                    Polynomial Degree
     * @param        k                                    Number of Ring-Learning-With-Errors Samples
     * @param        h                                    Number of Non-Zero Entries of Output Elements of Encryption
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
     *************************************************************************************************************************/
    private static int verifying(

        byte[] message,
        final byte[] signature, int signatureOffset, int signatureLength,
        final byte[] publicKey,
        int n, int k, int h, int q, long qInverse, int qLogarithm, int b, int d, int u, int signatureSize,
        int generatorA, int inverseNumberTheoreticTransform,
        int barrettMultiplication, int barrettDivision,
        long[] zeta

    )
    {

        byte[] C = new byte[Polynomial.HASH];
        byte[] cSignature = new byte[Polynomial.HASH];
        byte[] seed = new byte[Polynomial.SEED];
        byte[] hashMessage = new byte[Polynomial.MESSAGE];
        int[] newPublicKey = new int[n * k];

        int[] positionList = new int[h];
        short[] signList = new short[h];

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

            Pack.decodeSignatureIP(C, Z, signature, signatureOffset);

        }

        if (q == Parameter.Q_III_P)
        {

            Pack.decodeSignatureIIIP(C, Z, signature, signatureOffset);

        }

        /* Check Norm of Z */
        if (testZ(Z, n, b, u) == true)
        {

            return -2;

        }

        if (q == Parameter.Q_I_P)
        {

            Pack.decodePublicKeyIP(newPublicKey, seed, 0, publicKey);

        }

        if (q == Parameter.Q_III_P)
        {

            Pack.decodePublicKeyIIIP(newPublicKey, seed, 0, publicKey);

        }

        /* Generate A Polynomial */
        Polynomial.polynomialUniform(A, seed, 0, n, k, q, qInverse, qLogarithm, generatorA, inverseNumberTheoreticTransform);

        Sample.encodeC(positionList, signList, C, 0, n, h);

        Polynomial.polynomialNumberTheoreticTransform(numberTheoreticTransformZ, Z, n);

        /* W_i = A_i * Z_i - TC_i for All i */
        for (int i = 0; i < k; i++)
        {

            Polynomial.polynomialMultiplication(W, n * i, A, n * i, numberTheoreticTransformZ, 0, n, q, qInverse);

            Polynomial.sparsePolynomialMultiplication32(
                TC, n * i, newPublicKey, n * i, positionList, signList, n, h, q, barrettMultiplication, barrettDivision
            );

            Polynomial.polynomialSubtraction(W, n * i, W, n * i, TC, n * i, n, q, barrettMultiplication, barrettDivision);

        }

        if (q == Parameter.Q_I_P)
        {

            HashUtils.secureHashAlgorithmKECCAK128(
                hashMessage, 0, Polynomial.MESSAGE, message, 0, message.length
            );

        }

        if (q == Parameter.Q_III_P)
        {

            HashUtils.secureHashAlgorithmKECCAK256(
                hashMessage, 0, Polynomial.MESSAGE, message, 0, message.length
            );

        }

        /* Obtain the Hash Symbol */
        hashFunction(cSignature, 0, W, hashMessage, 0, n, k, d, q);

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
            Parameter.N_I_P, Parameter.K_I_P, Parameter.H_I_P,
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
            Parameter.N_III_P, Parameter.K_III_P, Parameter.H_III_P,
            Parameter.Q_III_P, Parameter.Q_INVERSE_III_P, Parameter.Q_LOGARITHM_III_P,
            Parameter.B_III_P, Parameter.D_III_P, Parameter.U_III_P, Polynomial.SIGNATURE_III_P,
            Parameter.GENERATOR_A_III_P, Parameter.INVERSE_NUMBER_THEORETIC_TRANSFORM_III_P,
            Parameter.BARRETT_MULTIPLICATION_III_P, Parameter.BARRETT_DIVISION_III_P,
            PolynomialProvablySecure.ZETA_III_P
        );
    }

}
