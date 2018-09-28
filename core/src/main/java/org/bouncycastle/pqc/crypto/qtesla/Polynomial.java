package org.bouncycastle.pqc.crypto.qtesla;

class Polynomial
{

    /**
     * Size of A Random Number (in Byte)
     */
    public static final int RANDOM = 32;

    /**
     * Size of A Seed (in Byte)
     */
    public static final int SEED = 32;

    /**
     * Size of Hash Value C (in Byte) in the Signature Package
     */
    public static final int HASH = 32;

    /**
     * Size of the Signature Package (Z, C) (in Byte) for Heuristic qTESLA Security Category-1.
     * Z is A Polynomial Bounded by B and C is the Output of A Hashed String
     */
    public static final int SIGNATURE_I = (Parameter.N_I * Parameter.D_I + 7) / 8 + HASH;

    /**
     * Size of the Signature Package (Z, C) (in Byte) for Heuristic qTESLA Security Category-3 (Option for Size).
     * Z is A Polynomial Bounded by B and C is the Output of A Hashed String
     */
    public static final int SIGNATURE_III_SIZE = (Parameter.N_III_SIZE * Parameter.D_III_SIZE + 7) / 8 + HASH;

    /**
     * Size of the Signature Package (Z, C) (in Byte) for Heuristic qTESLA Security Category-3 (Option for Speed).
     * Z is A Polynomial Bounded by B and C is the Output of A Hashed String
     */
    public static final int SIGNATURE_III_SPEED = (Parameter.N_III_SPEED * Parameter.D_III_SPEED + 7) / 8 + HASH;

    /**
     * Size of the Signature Package (Z, C) (in Byte) for Provably-Secure qTESLA Security Category-1.
     * Z is A Polynomial Bounded by B and C is the Output of A Hashed String
     */
    public static final int SIGNATURE_I_P = (Parameter.N_I_P * Parameter.D_I_P + 7) / 8 + HASH;

    /**
     * Size of the Signature Package (Z, C) (in Byte) for Provably-Secure qTESLA Security Category-3.
     * Z is A Polynomial Bounded by B and C is the Output of A Hashed String
     */
    public static final int SIGNATURE_III_P = (Parameter.N_III_P * Parameter.D_III_P + 7) / 8 + HASH;

    /**
     * Size of the Public Key (in Byte) Containing seedA and Polynomial T for Heuristic qTESLA Security Category-1
     */
    public static final int PUBLIC_KEY_I = (Parameter.N_I * Parameter.K_I * Parameter.Q_LOGARITHM_I + 7) / 8 + SEED;

    /**
     * Size of the Public Key (in Byte) Containing seedA and Polynomial T for Heuristic qTESLA Security Category-3 (Option for Size)
     */
    public static final int PUBLIC_KEY_III_SIZE = (Parameter.N_III_SIZE * Parameter.K_III_SIZE * Parameter.Q_LOGARITHM_III_SIZE + 7) / 8 + SEED;

    /**
     * Size of the Public Key (in Byte) Containing seedA and Polynomial T for Heuristic qTESLA Security Category-3 (Option for Speed)
     */
    public static final int PUBLIC_KEY_III_SPEED = (Parameter.N_III_SPEED * Parameter.K_III_SPEED * Parameter.Q_LOGARITHM_III_SPEED + 7) / 8 + SEED;

    /**
     * Size of the Public Key (in Byte) Containing seedA and Polynomial T for Provably-Secure qTESLA Security Category-1
     */
    public static final int PUBLIC_KEY_I_P = (Parameter.N_I_P * Parameter.K_I_P * Parameter.Q_LOGARITHM_I_P + 7) / 8 + SEED;

    /**
     * Size of the Public Key (in Byte) Containing seedA and Polynomial T for Provably-Secure qTESLA Security Category-3
     */
    public static final int PUBLIC_KEY_III_P = (Parameter.N_III_P * Parameter.K_III_P * Parameter.Q_LOGARITHM_III_P + 7) / 8 + SEED;

    /**
     * Size of the Private Key (in Byte) Containing Polynomials (Secret Polynomial and Error Polynomial) and Seeds (seedA and seedY)
     * for Heuristic qTESLA Security Category-1
     */
    public static final int PRIVATE_KEY_I = Parameter.N_I * Short.SIZE / Byte.SIZE * 2 + SEED * 2;

    /**
     * Size of the Private Key (in Byte) Containing Polynomials (Secret Polynomial and Error Polynomial) and Seeds (seedA and seedY)
     * for Heuristic qTESLA Security Category-3 (Option for Size)
     */
    public static final int PRIVATE_KEY_III_SIZE = Parameter.N_III_SIZE * Short.SIZE / Byte.SIZE * 2 + SEED * 2;

    /**
     * Size of the Private Key (in Byte) Containing Polynomials (Secret Polynomial and Error Polynomial) and Seeds (seedA and seedY)
     * for Heuristic qTESLA Security Category-3 (Option for Speed)
     */
    public static final int PRIVATE_KEY_III_SPEED = Parameter.N_III_SPEED * Short.SIZE / Byte.SIZE * 2 + SEED * 2;

    /**
     * Size of the Private Key (in Byte) Containing Polynomials (Secret Polynomial and Error Polynomial) and Seeds (seedA and seedY)
     * for Provably-Secure qTESLA Security Category-1
     */
    public static final int PRIVATE_KEY_I_P = Parameter.N_I_P + Parameter.N_I_P * Parameter.K_I_P + SEED * 2;

    /**
     * Size of the Private Key (in Byte) Containing Polynomials (Secret Polynomial and Error Polynomial) and Seeds (seedA and seedY)
     * for Provably-Secure qTESLA Security Category-3
     */
    public static final int PRIVATE_KEY_III_P = Parameter.N_III_P + Parameter.N_III_P * Parameter.K_III_P + SEED * 2;

    /*******************************************************************
     * Description:	Montgomery Reduction
     *
     * @param        a        Number to be Reduced
     * @param        q            Modulus
     * @param        qInverse
     *
     * @return Reduced Number
     *******************************************************************/
    private static long montgomery(long a, int q, long qInverse)
    {
        long u = (a * qInverse) & 0xFFFFFFFFL;

        u *= q;
        a += u;

        return a >> 32;

    }

    /********************************************************************************************
     * Description:	Barrett Reduction for Heuristic qTESLA Security Category-1 and Category-3
     * 				(Option for Size or Speed)
     *
     * @param        number                    Number to be Reduced
     * @param        barrettMultiplication
     * @param        barrettDivision
     * @param        q                        Modulus
     *
     * @return Reduced Number
     ********************************************************************************************/
    public static int barrett(long number, int q, int barrettMultiplication, int barrettDivision)
    {

        long u =  ((number * barrettMultiplication) >> barrettDivision) * q;
        
        return (int)(number - u);

    }

    /**********************************************************************************************
     * Description:	Barrett Reduction for Provably-Secure qTESLA Security Category-1 and Category-3
     *
     * @param        number                    Number to be Reduced
     * @param        barrettMultiplication
     * @param        barrettDivision
     * @param        q                        Modulus
     *
     * @return Reduced Number
     **********************************************************************************************/
    static long barrettP(long number, int q, int barrettMultiplication, int barrettDivision)
    {

        long u = ((number * barrettMultiplication) >> barrettDivision) * q;

        return number - u;

    }

    /**************************************************************************************************************
     * Description:	Forward Number Theoretic Transform for Heuristic qTESLA Security Category-1, Category-3
     *				(Option for Size and Speed) and Provably-Secure qTESLA Security Category-1
     *
     * @param        destination        Destination of Transformation
     * @param        source            Source of Transformation
     * @param        n                Polynomial Degree
     * @param        q                Modulus
     * @param        qInverse
     *
     * @return none
     **************************************************************************************************************/
    private static void numberTheoreticTransform(long destination[], long source[], int n, int q, long qInverse)
    {
        int jTwiddle = 0;
        int numberOfProblem = n >> 1;

        for (; numberOfProblem > 0; numberOfProblem >>= 1)
        {

            int j = 0;
            int jFirst;

            for (jFirst = 0; jFirst < n; jFirst = j + numberOfProblem)
            {
                int omega = (int)source[jTwiddle++];

                for (j = jFirst; j < jFirst + numberOfProblem; j++)
                {
                    int temporary = (int)montgomery(omega * destination[j + numberOfProblem], q, qInverse);

                    destination[j + numberOfProblem] = destination[j] + (q - temporary);
                    destination[j] = destination[j] + temporary;

                }
            }

        }
    }

    /**************************************************************************************************************
     * Description:	Forward Number Theoretic Transform for Provably-Secure qTESLA Security Category-3
     *
     * @param        destination        Destination of Transformation
     * @param        source            Source of Transformation
     *
     * @return none
     **************************************************************************************************************/
    private static void numberTheoreticTransform(long destination[], long source[])
    {

        int jTwiddle = 0;
        int numberOfProblem = Parameter.N_III_P >> 1;

        for (; numberOfProblem > 0; numberOfProblem >>= 1)
        {

            int j = 0;
            int jFirst;

            for (jFirst = 0; jFirst < Parameter.N_III_P; jFirst = j + numberOfProblem)
            {

                int omega = (int)source[jTwiddle++];

                for (j = jFirst; j < jFirst + numberOfProblem; j++)
                {

                    int temporary = (int)barrettP(
                        montgomery(
                            omega * destination[j + numberOfProblem],
                            Parameter.Q_III_P,
                            Parameter.Q_INVERSE_III_P
                        ),
                        Parameter.Q_III_P,
                        Parameter.BARRETT_MULTIPLICATION_III_P,
                        Parameter.BARRETT_DIVISION_III_P
                    );

                    destination[j + numberOfProblem] = barrettP(
                        destination[j] + Parameter.Q_III_P * 2L - temporary,
                        Parameter.Q_III_P,
                        Parameter.BARRETT_MULTIPLICATION_III_P,
                        Parameter.BARRETT_DIVISION_III_P
                    );

                    destination[j] = barrettP(
                        destination[j] + temporary,
                        Parameter.Q_III_P,
                        Parameter.BARRETT_MULTIPLICATION_III_P,
                        Parameter.BARRETT_DIVISION_III_P
                    );

                }

            }

        }

    }

    /****************************************************************************************************************************************************************************
     * Description:	Inverse Number Theoretic Transform for Heuristic qTESLA Security Category-1
     *
     * @param        destination            Destination of Inverse Transformation
     * @param        destinationOffset    Starting Point of the Destination
     * @param        source                Source of Inverse Transformation
     * @param        sourceOffset        Starting Point of the Source
     *
     * @return none
     ****************************************************************************************************************************************************************************/
    private static void inverseNumberTheoreticTransformI(long destination[], int destinationOffset, long source[], int sourceOffset)
    {

        int jTwiddle = 0;

        for (int numberOfProblem = 1; numberOfProblem < Parameter.N_I; numberOfProblem *= 2)
        {

            int j = 0;
            int jFirst;

            for (jFirst = 0; jFirst < Parameter.N_I; jFirst = j + numberOfProblem)
            {

                int omega = (int)source[sourceOffset + (jTwiddle++)];

                for (j = jFirst; j < jFirst + numberOfProblem; j++)
                {

                    int temporary = (int)destination[destinationOffset + j];

                    destination[destinationOffset + j] = barrett(
                        destination[destinationOffset + j + numberOfProblem] + temporary,
                        Parameter.Q_I, Parameter.BARRETT_MULTIPLICATION_I, Parameter.BARRETT_DIVISION_I
                    );

                    destination[destinationOffset + j + numberOfProblem] = montgomery(
                        omega * (Parameter.Q_I * 2 + temporary - destination[destinationOffset + j + numberOfProblem]),
                        Parameter.Q_I, Parameter.Q_INVERSE_I
                    );

                }

            }

        }

    }

    /**************************************************************************************************************************************************************************************************************
     * Description:	Inverse Number Theoretic Transform for Heuristic qTESLA Security Category-3 (Option for Size and Speed) and Provably-Secure qTESLA Security Category-1
     *
     * @param        a                    Destination of Inverse Transformation
     * @param        aOff            Starting Point of the Destination
     * @param        w                        Source of Inverse Transformation
     * @param        wOff                Starting Point of the Source
     * @param        n                            Polynomial Degree
     * @param        q                            Modulus
     * @param        qInverse
     * @param        barrettMultiplication
     * @param        barrettDivision
     *
     * @return none
     **************************************************************************************************************************************************************************************************************/
    private static void inverseNumberTheoreticTransform(long a[], int aOff, long w[], int wOff, int n, int q, long qInverse, int barrettMultiplication, int barrettDivision)
    {

        int jTwiddle = 0;

        for (int numberOfProblem = 1; numberOfProblem < n; numberOfProblem *= 2)
        {

            int j = 0;
            int jFirst;

            for (jFirst = 0; jFirst < n; jFirst = j + numberOfProblem)
            {

                int omega = (int)w[wOff + (jTwiddle++)];

                for (j = jFirst; j < jFirst + numberOfProblem; j++)
                {

                    int temporary = (int)a[aOff + j];

                    a[aOff + j] = a[aOff + j + numberOfProblem] + temporary;

                    a[aOff + j + numberOfProblem] = montgomery(omega * (temporary + (2 * q -  a[aOff + j + numberOfProblem])), q, qInverse);

                }

            }

            numberOfProblem *= 2;

            for (jFirst = 0; jFirst < n; jFirst = j + numberOfProblem)
            {

                int omega = (int)w[wOff + (jTwiddle++)];

                for (j = jFirst; j < jFirst + numberOfProblem; j++)
                {

                    int temporary = (int)a[aOff + j];

                    if (q == Parameter.Q_III_SIZE || q == Parameter.Q_III_SPEED)
                    {

                        a[aOff + j] = barrett(
                            a[aOff + j + numberOfProblem] + temporary,
                            q, barrettMultiplication, barrettDivision
                        );
                    }

                    if (q == Parameter.Q_I_P)
                    {

                        a[aOff + j] = barrettP(
                            a[aOff + j + numberOfProblem] + temporary,
                            q, barrettMultiplication, barrettDivision
                        );
                    }

                    a[aOff + j + numberOfProblem] = montgomery(omega * (q * 2L + temporary - a[aOff + j + numberOfProblem]), q, qInverse);

                }

            }

        }

    }

    /******************************************************************************************************************************************************************************************
     * Description:	Inverse Number Theoretic Transform for Provably-Secure qTESLA Security Category-3
     *
     * @param        destination            Destination of Inverse Transformation
     * @param        destinationOffset    Starting Point of the Destination
     * @param        source                Source of Inverse Transformation
     * @param        sourceOffset        Starting Point of the Source
     *
     * @return none
     ******************************************************************************************************************************************************************************************/
    private static void inverseNumberTheoreticTransformIIIP(long destination[], int destinationOffset, long source[], int sourceOffset)
    {

        int jTwiddle = 0;

        for (int numberOfProblem = 1; numberOfProblem < Parameter.N_III_P; numberOfProblem *= 2)
        {

            int j = 0;
            int jFirst;

            for (jFirst = 0; jFirst < Parameter.N_III_P; jFirst = j + numberOfProblem)
            {

                int omega = (int)source[sourceOffset + (jTwiddle++)];

                for (j = jFirst; j < jFirst + numberOfProblem; j++)
                {

                    int temporary = (int)destination[destinationOffset + j];

                    destination[destinationOffset + j] = barrettP(
                        destination[destinationOffset + j + numberOfProblem] + temporary,
                        Parameter.Q_III_P, Parameter.BARRETT_MULTIPLICATION_III_P, Parameter.BARRETT_DIVISION_III_P
                    );

                    destination[destinationOffset + j + numberOfProblem] = barrettP(
                        montgomery(
                            omega * (Parameter.Q_III_P * 2L + temporary - destination[destinationOffset + j + numberOfProblem]),
                            Parameter.Q_III_P, Parameter.Q_INVERSE_III_P
                        ),
                        Parameter.Q_III_P, Parameter.BARRETT_MULTIPLICATION_III_P, Parameter.BARRETT_DIVISION_III_P
                    );

                }

            }

        }

    }

    /*****************************************************************************************************************************************************************************************************************
     * Description:	Component Wise Polynomial Multiplication
     *
     * @param        product                    Product = Multiplicand (*) Multiplier
     * @param        productOffset            Starting Point of the Product Array
     * @param        multiplicand            Multiplicand Array
     * @param        multiplicandOffset        Starting Point of the Multiplicand Array
     * @param        multiplier                Multiplier Array
     * @param        multiplierOffset        Starting Point of the Multiplier Array
     * @param        n                        Polynomial Degree
     * @param        q                        Modulus
     * @param        qInverse
     *
     * @return none
     *****************************************************************************************************************************************************************************************************************/
    private static void componentWisePolynomialMultiplication(long[] product, int productOffset, long[] multiplicand, int multiplicandOffset, long[] multiplier, int multiplierOffset, int n, int q, long qInverse)
    {

        for (int i = 0; i < n; i++)
        {

            product[productOffset + i] = montgomery(multiplicand[multiplicandOffset + i] * multiplier[multiplierOffset + i], q, qInverse);

        }

    }

    /***********************************************************************************************************************************************
     * Description:	Polynomial Number Theoretic Transform for Provably-Secure qTESLA Security Category-1 and Category-3
     *
     * @param        arrayNumberTheoreticTransform        Transformed Array
     * @param        array                                Array to be Transformed
     * @param        n                                    Polynomial Degree
     *
     * @return none
     ***********************************************************************************************************************************************/
    public static void polynomialNumberTheoreticTransform(long[] arrayNumberTheoreticTransform, long[] array, int n)
    {

        for (int i = 0; i < n; i++)
        {

            arrayNumberTheoreticTransform[i] = array[i];

        }

        if (n == Parameter.N_I_P)
        {

            numberTheoreticTransform(arrayNumberTheoreticTransform, PolynomialProvablySecure.ZETA_I_P, n, Parameter.Q_I_P, Parameter.Q_INVERSE_I_P);

        }

        if (n == Parameter.N_III_P)
        {

            numberTheoreticTransform(arrayNumberTheoreticTransform, PolynomialProvablySecure.ZETA_III_P);

        }

    }

    /****************************************************************************************************************************************************************************************************************
     * Description:	Polynomial Multiplication for Heuristic qTESLA Security Category-1 and Category-3 (Option for Size and Speed)
     *
     * @param        product                    Product = Multiplicand * Multiplier
     * @param        productOffset            Starting Point of the Product Array
     * @param        multiplicand            Multiplicand Array
     * @param        multiplicandOffset        Starting Point of the Multiplicand Array
     * @param        multiplier                Multiplier Array
     * @param        multiplier                Starting Point of the Multiplier Array
     * @param        n                        Polynomial Degree
     * @param        q                        Modulus
     * @param        qInverse
     * @param        zeta
     *
     * @return none
     ****************************************************************************************************************************************************************************************************************/
    public static void polynomialMultiplication(long[] product, int productOffset, long[] multiplicand, int multiplicandOffset, long[] multiplier, int multiplierOffset, int n, int q, long qInverse, long[] zeta)
    {

        long[] multiplierNumberTheoreticTransform = new long[n];

        for (int i = 0; i < n; i++)
        {
            multiplierNumberTheoreticTransform[i] = multiplier[multiplierOffset + i];
        }

        numberTheoreticTransform(multiplierNumberTheoreticTransform, zeta, n, q, qInverse);

        componentWisePolynomialMultiplication(product, productOffset, multiplicand, multiplicandOffset, multiplierNumberTheoreticTransform, 0, n, q, qInverse);

        if (q == Parameter.Q_I)
        {

            inverseNumberTheoreticTransformI(product, productOffset, PolynomialHeuristic.ZETA_INVERSE_I, 0);

        }

        if (q == Parameter.Q_III_SIZE)
        {

            inverseNumberTheoreticTransform(
                product, productOffset, PolynomialHeuristic.ZETA_INVERSE_III_SIZE, 0,
                Parameter.N_III_SIZE, Parameter.Q_III_SIZE, Parameter.Q_INVERSE_III_SIZE,
                Parameter.BARRETT_MULTIPLICATION_III_SIZE, Parameter.BARRETT_DIVISION_III_SIZE
            );

        }

        if (q == Parameter.Q_III_SPEED)
        {

            inverseNumberTheoreticTransform(
                product, productOffset, PolynomialHeuristic.ZETA_INVERSE_III_SPEED, 0,
                Parameter.N_III_SPEED, Parameter.Q_III_SPEED, Parameter.Q_INVERSE_III_SPEED,
                Parameter.BARRETT_MULTIPLICATION_III_SPEED, Parameter.BARRETT_DIVISION_III_SPEED
            );

        }

    }

    /***************************************************************************************************************************************************************************************************
     * Description:	Polynomial Multiplication for Provably-Secure qTESLA Security Category-1 and Category-3
     *
     * @param        product                    Product = Multiplicand * Multiplier
     * @param        productOffset            Starting Point of the Product Array
     * @param        multiplicand            Multiplicand Array
     * @param        multiplicandOffset        Starting Point of the Multiplicand Array
     * @param        multiplier                Multiplier Array
     * @param        multiplierOffset        Starting Point of the Multiplier Array
     * @param        n                        Polynomial Degree
     * @param        q                        Modulus
     * @param        qInverse
     *
     * @return none
     ***************************************************************************************************************************************************************************************************/
    public static void polynomialMultiplication(long[] product, int productOffset, long[] multiplicand, int multiplicandOffset, long[] multiplier, int multiplierOffset, int n, int q, long qInverse)
    {

        componentWisePolynomialMultiplication(product, productOffset, multiplicand, multiplicandOffset, multiplier, multiplierOffset, n, q, qInverse);

        if (q == Parameter.Q_I_P)
        {

            inverseNumberTheoreticTransform(
                product, productOffset, PolynomialProvablySecure.ZETA_INVERSE_I_P, 0,
                Parameter.N_I_P, Parameter.Q_I_P, Parameter.Q_INVERSE_I_P, Parameter.BARRETT_MULTIPLICATION_I_P, Parameter.BARRETT_DIVISION_I_P
            );

        }

        if (q == Parameter.Q_III_P)
        {

            inverseNumberTheoreticTransformIIIP(product, productOffset, PolynomialProvablySecure.ZETA_INVERSE_III_P, 0);

        }

    }

    /********************************************************************************************************************************************************
     * Description:	Polynomial Addition
     * 				Q + L_E < 2 ^ (CEIL (LOGARITHM (Q, 2)))
     * 				No Necessary Reduction for Y + SC
     *
     * @param        summation            Summation = Augend + Addend
     * @param        summationOffset        Starting Point of the Summation Array
     * @param        augend                Augend Array
     * @param        augendOffset        Starting Point of the Augend Array
     * @param        addend                Addend Array
     * @param        addendOffset        Starting Point of the Addend Array
     * @param        n                    Polynomial Degree
     *
     * @return none
     ********************************************************************************************************************************************************/
    public static void polynomialAddition(long[] summation, int summationOffset, long[] augend, int augendOffset, long[] addend, int addendOffset, int n)
    {

        for (int i = 0; i < n; i++)
        {

            summation[summationOffset + i] = augend[augendOffset + i] + addend[addendOffset + i];

        }

    }

    /******************************************************************************************************************************************************************************************************************************
     * Description:	Polynomial Subtraction for Heuristic qTESLA Security Category-1 and Category-3 (Option for Size or Speed)
     *
     * @param        difference                    Difference = Minuend (-) Subtrahend
     * @param        differenceOffset            Starting Point of the Difference Array
     * @param        minuend                        Minuend Array
     * @param        minuendOffset                Starting Point of the Minuend Array
     * @param        subtrahend                    Subtrahend Array
     * @param        subtrahendOffset            Starting Point of the Subtrahend Array
     * @param        n                            Polynomial Degree
     * @param        q                            Modulus
     * @param        barrettMultiplication
     * @param        barrettDivision
     *
     * @return none
     ******************************************************************************************************************************************************************************************************************************/
    public static void polynomialSubtraction(long[] difference, int differenceOffset, long[] minuend, int minuendOffset, long[] subtrahend, int subtrahendOffset, int n, int q, int barrettMultiplication, int barrettDivision)
    {
        for (int i = 0; i < n; i++)
        {
            difference[differenceOffset + i] = barrett(q * 2 + minuend[minuendOffset + i] - subtrahend[subtrahendOffset + i], q, barrettMultiplication, barrettDivision);
        }
    }

    /*******************************************************************************************************************************************************************************************************************************
     * Description:	Polynomial Subtraction for Provably-Secure qTESLA Security Category-1 and Category-3
     *
     * @param        difference                    Difference = Minuend (-) Subtrahend
     * @param        differenceOffset            Starting Point of the Difference Array
     * @param        minuend                        Minuend Array
     * @param        minuendOffset                Starting Point of the Minuend Array
     * @param        subtrahend                    Subtrahend Array
     * @param        subtrahendOffset            Starting Point of the Subtrahend Array
     * @param        n                            Polynomial Degree
     * @param        q                            Modulus
     * @param        barrettMultiplication
     * @param        barrettDivision
     *
     * @return none
     *******************************************************************************************************************************************************************************************************************************/
    public static void polynomialSubtractionP(long[] difference, int differenceOffset, long[] minuend, int minuendOffset, long[] subtrahend, int subtrahendOffset, int n, int q, int barrettMultiplication, int barrettDivision)
    {
        for (int i = 0; i < n; i++)
        {
            difference[differenceOffset + i] = barrettP(minuend[minuendOffset + i] - subtrahend[subtrahendOffset + i], q, barrettMultiplication, barrettDivision);
        }
    }

    /**************************************************************************************************************************************************************************************
     * Description:	Generation of Polynomial A
     *
     * @param        A                                    Polynomial to be Generated
     * @param        seed                                Kappa-Bit Seed
     * @param        seedOffset                            Starting Point of the Kappa-Bit Seed
     * @param        n                                    Polynomial Degree
     * @param        k                                    Number of Ring-Learning-With-Errors Samples
     * @param        q                                    Modulus
     * @param        qInverse
     * @param        qLogarithm                            q <= 2 ^ qLogarithm
     * @param        generatorA
     * @param        inverseNumberTheoreticTransform
     *
     * @return none
     **************************************************************************************************************************************************************************************/
    public static void polynomialUniform(long[] A, byte[] seed, int seedOffset, int n, int k, int q, long qInverse, int qLogarithm, int generatorA, int inverseNumberTheoreticTransform)
    {

        int position = 0;
        int i = 0;
        int numberOfByte = (qLogarithm + 7) / 8;
        int numberOfBlock = generatorA;
        short dualModeSampler = 0;
        int value1;
        int value2;
        int value3;
        int value4;
        int mask = (1 << qLogarithm) - 1;

        byte[] buffer = new byte[HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * numberOfBlock];

        HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(
            buffer, 0, HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * numberOfBlock,
            dualModeSampler++,
            seed, seedOffset, RANDOM
        );

        while (i < n * k)
        {

            if (position > (HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * numberOfBlock - Integer.SIZE / Byte.SIZE * numberOfByte))
            {

                numberOfBlock = 1;

                HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(
                    buffer, 0, HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * numberOfBlock,
                    dualModeSampler++,
                    seed, seedOffset, RANDOM
                );
     
                position = 0;

            }

            value1 = CommonFunction.load32(buffer, position) & mask;
            position += numberOfByte;

            value2 = CommonFunction.load32(buffer, position) & mask;
            position += numberOfByte;

            value3 = CommonFunction.load32(buffer, position) & mask;
            position += numberOfByte;

            value4 = CommonFunction.load32(buffer, position) & mask;
            position += numberOfByte;

            if (value1 < q && i < n * k)
            {

                A[i++] = montgomery((long)value1 * inverseNumberTheoreticTransform, q, qInverse);
            }

            if (value2 < q && i < n * k)
            {

                A[i++] = montgomery((long)value2 * inverseNumberTheoreticTransform, q, qInverse);

            }

            if (value3 < q && i < n * k)
            {

                A[i++] = montgomery((long)value3 * inverseNumberTheoreticTransform, q, qInverse);

            }

            if (value4 < q && i < n * k)
            {

                A[i++] = montgomery((long)value4 * inverseNumberTheoreticTransform, q, qInverse);

            }

        }

    }

}
