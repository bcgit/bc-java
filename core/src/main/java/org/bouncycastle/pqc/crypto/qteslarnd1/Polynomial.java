package org.bouncycastle.pqc.crypto.qteslarnd1;

import org.bouncycastle.util.Arrays;

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
     * Size of Hashed Message
     */
    public static final int MESSAGE = 64;

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
    public static final int PRIVATE_KEY_I = Parameter.N_I * Parameter.S_BIT_I / Const.BYTE_SIZE * 2 + SEED * 2;

    /**
     * Size of the Private Key (in Byte) Containing Polynomials (Secret Polynomial and Error Polynomial) and Seeds (seedA and seedY)
     * for Heuristic qTESLA Security Category-3 (Option for Size)
     */
    public static final int PRIVATE_KEY_III_SIZE = Parameter.N_III_SIZE * Parameter.S_BIT_III_SIZE / Const.BYTE_SIZE * 2 + SEED * 2;

    /**
     * Size of the Private Key (in Byte) Containing Polynomials (Secret Polynomial and Error Polynomial) and Seeds (seedA and seedY)
     * for Heuristic qTESLA Security Category-3 (Option for Speed)
     */
    public static final int PRIVATE_KEY_III_SPEED = Parameter.N_III_SPEED * Parameter.S_BIT_III_SPEED / Const.BYTE_SIZE * 2 + SEED * 2;

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

    /****************************************************************************
     * Description:	Montgomery Reduction for Heuristic qTESLA Security Category 1
     * 				and Security Category-3 (Option for Size and Speed)
     *
     * @param        number        Number to be Reduced
     * @param        q            Modulus
     * @param        qInverse
     *
     * @return Reduced Number
     ****************************************************************************/
    private static int montgomery(long number, int q, long qInverse)
    {

        return (int)((number + ((number * qInverse) & 0xFFFFFFFFL) * q) >> 32);

    }

    /****************************************************************************
     * Description:	Montgomery Reduction for Provably-Secure qTESLA
     * 				Security Category-1 and Security Category-3
     *
     * @param        number        Number to be Reduced
     * @param        q            Modulus
     * @param        qInverse
     *
     * @return Reduced Number
     ****************************************************************************/
    private static long montgomeryP(long number, int q, long qInverse)
    {

        return (number + ((number * qInverse) & 0xFFFFFFFFL) * q) >> 32;

    }

    /**********************************************************************************************
     * Description:	Barrett Reduction for Heuristic qTESLA Security Category-3
     * 				(Option for Size or Speed)
     *
     * @param        number                    Number to be Reduced
     * @param        barrettMultiplication
     * @param        barrettDivision
     * @param        q                        Modulus
     *
     * @return Reduced Number
     **********************************************************************************************/
    public static int barrett(int number, int q, int barrettMultiplication, int barrettDivision)
    {

        return number - (int)(((long)number * barrettMultiplication) >> barrettDivision) * q;

    }

    /*************************************************************************************************
     * Description:	Barrett Reduction for Provably-Secure qTESLA Security Category-1 and
     * 				Security Category-3
     *
     * @param        number                    Number to be Reduced
     * @param        barrettMultiplication
     * @param        barrettDivision
     * @param        q                        Modulus
     *
     * @return Reduced Number
     *************************************************************************************************/
    public static long barrett(long number, int q, int barrettMultiplication, int barrettDivision)
    {

        return number - ((number * barrettMultiplication) >> barrettDivision) * q;

    }

    /************************************************************************************************************
     * Description:	Forward Number Theoretic Transform for Heuristic qTESLA Security Category-1,
     * 				Security Category-3 (Option for Size and Speed)
     *
     * @param        destination        Destination of Transformation
     * @param        source            Source of Transformation
     * @param        n                Polynomial Degree
     * @param        q                Modulus
     * @param        qInverse
     *
     * @return none
     ************************************************************************************************************/
    private static void numberTheoreticTransform(int destination[], int source[], int n, int q, long qInverse)
    {

        int jTwiddle = 0;
        int numberOfProblem = n >> 1;

        for (; numberOfProblem > 0; numberOfProblem >>= 1)
        {

            int j = 0;
            int jFirst;

            for (jFirst = 0; jFirst < n; jFirst = j + numberOfProblem)
            {

                long omega = source[jTwiddle++];

                for (j = jFirst; j < jFirst + numberOfProblem; j++)
                {

                    int temporary = montgomery(omega * destination[j + numberOfProblem], q, qInverse);

                    destination[j + numberOfProblem] = destination[j] - temporary;
                    destination[j] = destination[j] + temporary;

                }

            }

        }

    }

    /**************************************************************************************************************
     * Description:	Forward Number Theoretic Transform for Provably-Secure qTESLA Security Category-1
     *
     * @param        destination        Destination of Transformation
     * @param        source            Source of Transformation
     *
     * @return none
     **************************************************************************************************************/
    private static void numberTheoreticTransformIP(long destination[], long source[])
    {

        int numberOfProblem = Parameter.N_I_P >> 1;
        int jTwiddle = 0;

        for (; numberOfProblem > 0; numberOfProblem >>= 1)
        {

            int j = 0;
            int jFirst;

            for (jFirst = 0; jFirst < Parameter.N_I_P; jFirst = j + numberOfProblem)
            {

                long omega = source[jTwiddle++];

                for (j = jFirst; j < jFirst + numberOfProblem; j++)
                {

                    long temporary = montgomeryP(
                        omega * destination[j + numberOfProblem],
                        Parameter.Q_I_P, Parameter.Q_INVERSE_I_P
                    );

                    destination[j + numberOfProblem] = destination[j] + (Parameter.Q_I_P - temporary);

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
    private static void numberTheoreticTransformIIIP(long destination[], long source[])
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

                    long temporary = barrett(
                        montgomeryP(
                            omega * destination[j + numberOfProblem],
                            Parameter.Q_III_P,
                            Parameter.Q_INVERSE_III_P
                        ),
                        Parameter.Q_III_P,
                        Parameter.BARRETT_MULTIPLICATION_III_P,
                        Parameter.BARRETT_DIVISION_III_P
                    );

                    destination[j + numberOfProblem] = barrett(
                        destination[j] + (2L * Parameter.Q_III_P - temporary),
                        Parameter.Q_III_P,
                        Parameter.BARRETT_MULTIPLICATION_III_P,
                        Parameter.BARRETT_DIVISION_III_P
                    );

                    destination[j] = barrett(
                        destination[j] + temporary,
                        Parameter.Q_III_P,
                        Parameter.BARRETT_MULTIPLICATION_III_P,
                        Parameter.BARRETT_DIVISION_III_P
                    );

                }

            }

        }

    }

    /******************************************************************************************************************
     * Description:	Inverse Number Theoretic Transform for Heuristic qTESLA Security Category-1
     *
     * @param        destination            Destination of Inverse Transformation
     * @param        source                Source of Inverse Transformation
     *
     * @return none
     ******************************************************************************************************************/
    private static void inverseNumberTheoreticTransformI(int destination[], int source[])
    {

        int jTwiddle = 0;

        for (int numberOfProblem = 1; numberOfProblem < Parameter.N_I; numberOfProblem *= 2)
        {

            int j = 0;
            int jFirst;

            for (jFirst = 0; jFirst < Parameter.N_I; jFirst = j + numberOfProblem)
            {

                long omega = source[jTwiddle++];

                for (j = jFirst; j < jFirst + numberOfProblem; j++)
                {

                    int temporary = destination[j];

                    destination[j] = temporary + destination[j + numberOfProblem];

                    destination[j + numberOfProblem] = montgomery(
                        omega * (temporary - destination[j + numberOfProblem]),
                        Parameter.Q_I, Parameter.Q_INVERSE_I
                    );

                }

            }

        }

        for (int i = 0; i < Parameter.N_I / 2; i++)
        {

            destination[i] = montgomery((long)Parameter.R_I * destination[i], Parameter.Q_I, Parameter.Q_INVERSE_I);

        }

    }

    /**************************************************************************************************************************************************************************
     * Description:	Inverse Number Theoretic Transform for Heuristic qTESLA Security Category-3 (Option for Size and Speed)
     *
     * @param        destination                    Destination of Inverse Transformation
     * @param        source                        Source of Inverse Transformation
     * @param        n                            Polynomial Degree
     * @param        q                            Modulus
     * @param        qInverse
     * @param        r
     * @param        barrettMultiplication
     * @param        barrettDivision
     *
     * @return none
     **************************************************************************************************************************************************************************/
    private static void inverseNumberTheoreticTransform(int destination[], int source[], int n, int q, long qInverse, int r, int barrettMultiplication, int barrettDivision)
    {

        int jTwiddle = 0;

        for (int numberOfProblem = 1; numberOfProblem < n; numberOfProblem *= 2)
        {

            int j = 0;

            for (int jFirst = 0; jFirst < n; jFirst = j + numberOfProblem)
            {

                long omega = source[jTwiddle++];

                for (j = jFirst; j < jFirst + numberOfProblem; j++)
                {

                    int temporary = destination[j];

                    if (numberOfProblem == 16)
                    {

                        destination[j] = barrett(temporary + destination[j + numberOfProblem], q, barrettMultiplication, barrettDivision);

                    }
                    else
                    {

                        destination[j] = temporary + destination[j + numberOfProblem];

                    }

                    destination[j + numberOfProblem] = montgomery(omega * (temporary - destination[j + numberOfProblem]), q, qInverse);

                }

            }

        }

        for (int i = 0; i < n / 2; i++)
        {

            destination[i] = montgomery((long)r * destination[i], q, qInverse);

        }

    }

    /***********************************************************************************************************************************************************************************
     * Description:	Inverse Number Theoretic Transform for Provably-Secure qTESLA Security Category-1
     *
     * @param        destination            Destination of Inverse Transformation
     * @param        destinationOffset    Starting Point of the Destination
     * @param        source                Source of Inverse Transformation
     * @param        sourceOffset        Starting Point of the Source
     *
     * @return none
     ***********************************************************************************************************************************************************************************/
    private static void inverseNumberTheoreticTransformIP(long destination[], int destinationOffset, long source[], int sourceOffset)
    {

        int jTwiddle = 0;

        for (int numberOfProblem = 1; numberOfProblem < Parameter.N_I_P; numberOfProblem *= 2)
        {

            int j = 0;
            int jFirst;

            for (jFirst = 0; jFirst < Parameter.N_I_P; jFirst = j + numberOfProblem)
            {

                long omega = source[sourceOffset + (jTwiddle++)];

                for (j = jFirst; j < jFirst + numberOfProblem; j++)
                {

                    long temporary = destination[destinationOffset + j];

                    destination[destinationOffset + j] = temporary + destination[destinationOffset + j + numberOfProblem];

                    destination[destinationOffset + j + numberOfProblem] = montgomeryP(
                        omega * (temporary + (2L * Parameter.Q_I_P - destination[destinationOffset + j + numberOfProblem])),
                        Parameter.Q_I_P, Parameter.Q_INVERSE_I_P
                    );

                }

            }

            numberOfProblem *= 2;

            for (jFirst = 0; jFirst < Parameter.N_I_P; jFirst = j + numberOfProblem)
            {

                long omega = source[sourceOffset + (jTwiddle++)];

                for (j = jFirst; j < jFirst + numberOfProblem; j++)
                {

                    long temporary = destination[destinationOffset + j];

                    destination[destinationOffset + j] = barrett(
                        temporary + destination[destinationOffset + j + numberOfProblem],
                        Parameter.Q_I_P, Parameter.BARRETT_MULTIPLICATION_I_P, Parameter.BARRETT_DIVISION_I_P
                    );

                    destination[destinationOffset + j + numberOfProblem] = montgomeryP(
                        omega * (temporary + (2L * Parameter.Q_I_P - destination[destinationOffset + j + numberOfProblem])),
                        Parameter.Q_I_P, Parameter.Q_INVERSE_I_P
                    );

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

                long omega = source[sourceOffset + (jTwiddle++)];

                for (j = jFirst; j < jFirst + numberOfProblem; j++)
                {

                    long temporary = destination[destinationOffset + j];

                    destination[destinationOffset + j] = barrett(
                        temporary + destination[destinationOffset + j + numberOfProblem],
                        Parameter.Q_III_P, Parameter.BARRETT_MULTIPLICATION_III_P, Parameter.BARRETT_DIVISION_III_P
                    );

                    destination[destinationOffset + j + numberOfProblem] = barrett(
                        montgomeryP(
                            omega * (temporary + (2L * Parameter.Q_III_P - destination[destinationOffset + j + numberOfProblem])),
                            Parameter.Q_III_P, Parameter.Q_INVERSE_III_P
                        ),
                        Parameter.Q_III_P, Parameter.BARRETT_MULTIPLICATION_III_P, Parameter.BARRETT_DIVISION_III_P
                    );

                }

            }

        }

    }

    /****************************************************************************************************************************************************
     * Description:	Component Wise Polynomial Multiplication for Heuristic qTESLA Security Category-1 and Security Category-3 (Option for Size and Speed)
     *
     * @param        product                    Product = Multiplicand (*) Multiplier
     * @param        multiplicand            Multiplicand Array
     * @param        multiplier                Multiplier Array
     * @param        n                        Polynomial Degree
     * @param        q                        Modulus
     * @param        qInverse
     *
     * @return none
     ****************************************************************************************************************************************************/
    private static void componentWisePolynomialMultiplication(int[] product, int[] multiplicand, int[] multiplier, int n, int q, long qInverse)
    {

        for (int i = 0; i < n; i++)
        {

            product[i] = montgomery((long)multiplicand[i] * multiplier[i], q, qInverse);

        }

    }

    /******************************************************************************************************************************************************************************************************************
     * Description:	Component Wise Polynomial Multiplication for Provably-Secure qTESLA Security Category-1 and Security Category-3
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
     ******************************************************************************************************************************************************************************************************************/
    private static void componentWisePolynomialMultiplication(long[] product, int productOffset, long[] multiplicand, int multiplicandOffset, long[] multiplier, int multiplierOffset, int n, int q, long qInverse)
    {

        for (int i = 0; i < n; i++)
        {

            product[productOffset + i] = montgomeryP(multiplicand[multiplicandOffset + i] * multiplier[multiplierOffset + i], q, qInverse);

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

            numberTheoreticTransformIP(arrayNumberTheoreticTransform, PolynomialProvablySecure.ZETA_I_P);

        }

        if (n == Parameter.N_III_P)
        {

            numberTheoreticTransformIIIP(arrayNumberTheoreticTransform, PolynomialProvablySecure.ZETA_III_P);

        }

    }

    /*******************************************************************************************************************************************
     * Description:	Polynomial Multiplication for Heuristic qTESLA Security Category-1 and Category-3 (Option for Size and Speed)
     *
     * @param        product                    Product = Multiplicand * Multiplier
     * @param        multiplicand            Multiplicand Array
     * @param        multiplier                Multiplier Array
     * @param        n                        Polynomial Degree
     * @param        q                        Modulus
     * @param        qInverse
     * @param        zeta
     *
     * @return none
     *******************************************************************************************************************************************/
    public static void polynomialMultiplication(int[] product, int[] multiplicand, int[] multiplier, int n, int q, long qInverse, int[] zeta)
    {

        int[] multiplierNumberTheoreticTransform = new int[n];

        for (int i = 0; i < n; i++)
        {

            multiplierNumberTheoreticTransform[i] = multiplier[i];

        }

        numberTheoreticTransform(multiplierNumberTheoreticTransform, zeta, n, q, qInverse);

        componentWisePolynomialMultiplication(product, multiplicand, multiplierNumberTheoreticTransform, n, q, qInverse);

        if (q == Parameter.Q_I)
        {

            inverseNumberTheoreticTransformI(product, PolynomialHeuristic.ZETA_INVERSE_I);

        }

        if (q == Parameter.Q_III_SIZE)
        {

            inverseNumberTheoreticTransform(

                product, PolynomialHeuristic.ZETA_INVERSE_III_SIZE,
                Parameter.N_III_SIZE, Parameter.Q_III_SIZE, Parameter.Q_INVERSE_III_SIZE, Parameter.R_III_SIZE,
                Parameter.BARRETT_MULTIPLICATION_III_SIZE, Parameter.BARRETT_DIVISION_III_SIZE

            );

        }

        if (q == Parameter.Q_III_SPEED)
        {

            inverseNumberTheoreticTransform(

                product, PolynomialHeuristic.ZETA_INVERSE_III_SPEED,
                Parameter.N_III_SPEED, Parameter.Q_III_SPEED, Parameter.Q_INVERSE_III_SPEED, Parameter.R_III_SPEED,
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

            inverseNumberTheoreticTransformIP(product, productOffset, PolynomialProvablySecure.ZETA_INVERSE_I_P, 0);

        }

        if (q == Parameter.Q_III_P)
        {

            inverseNumberTheoreticTransformIIIP(product, productOffset, PolynomialProvablySecure.ZETA_INVERSE_III_P, 0);

        }

    }

    /****************************************************************************************************************************************************
     * Description:	Polynomial Addition for Heuristic qTESLA Security Category-1 and Category-3 (Option for Size or Speed)
     * 				Q + L_E < 2 ^ (CEIL (LOGARITHM (Q, 2)))
     * 				No Necessary Reduction for Y + SC
     *
     * @param        summation            Summation = Augend + Addend
     * @param        augend                Augend Array
     * @param        addend                Addend Array
     * @param        n                    Polynomial Degree
     *
     * @return none
     ****************************************************************************************************************************************************/
    public static void polynomialAddition(int[] summation, int[] augend, int[] addend, int n)
    {

        for (int i = 0; i < n; i++)
        {

            summation[i] = augend[i] + addend[i];

        }

    }

    /********************************************************************************************************************************************************
     * Description:	Polynomial Addition for Provably-Secure qTESLA Security Category-1 and Category-3
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

    /*************************************************************************************************************
     * Description:	Polynomial Addition with Correction for Heuristic qTESLA Security Category-1 and Category-3
     * 				(Option for Size or Speed)
     * 				Q + L_E < 2 ^ (CEIL (LOGARITHM (Q, 2)))
     * 				No Necessary Reduction for Y + SC
     *
     * @param        summation            Summation = Augend + Addend
     * @param        augend                Augend Array
     * @param        addend                Addend Array
     * @param        n                    Polynomial Degree
     *
     * @return none
     ************************************************************************************************************/
    public static void polynomialAdditionCorrection(int[] summation, int[] augend, int[] addend, int n, int q)
    {

        for (int i = 0; i < n; i++)
        {

            summation[i] = augend[i] + addend[i];
            /* If summation[i] < 0 Then Add Q */
            summation[i] += (summation[i] >> 31) & q;
            summation[i] -= q;
            /* If summation[i] >= Q Then Subtract Q */
            summation[i] += (summation[i] >> 31) & q;

        }

    }

    /**********************************************************************************************************************
     * Description:	Polynomial Subtraction with Correction for Heuristic qTESLA Security Category-1 and Security Category-3
     *				(Option for Size or Speed)
     *
     * @param        difference                    Difference = Minuend (-) Subtrahend
     * @param        minuend                        Minuend Array
     * @param        subtrahend                    Subtrahend Array
     * @param        n                            Polynomial Degree
     * @param        q                            Modulus
     *
     * @return none
     ***********************************************************************************************************************/
    public static void polynomialSubtractionCorrection(int[] difference, int[] minuend, int[] subtrahend, int n, int q)
    {

        for (int i = 0; i < n; i++)
        {

            difference[i] = minuend[i] - subtrahend[i];
            /* If difference[i] < 0 Then Add Q */
            difference[i] += (difference[i] >> 31) & q;

        }

    }

    /*******************************************************************************************************************************************
     * Description:	Polynomial Subtraction with Montgomery Reduction for Heuristic qTESLA Security Category-1 and Security Category-3
     *				(Option for Size or Speed)
     *
     * @param        difference                    Difference = Minuend (-) Subtrahend
     * @param        minuend                        Minuend Array
     * @param        subtrahend                    Subtrahend Array
     * @param        n                            Polynomial Degree
     * @param        q                            Modulus
     * @param        qInverse
     * @param        r
     *
     * @return none
     *******************************************************************************************************************************************/
    public static void polynomialSubtractionMontgomery(int[] difference, int[] minuend, int[] subtrahend, int n, int q, long qInverse, int r)
    {

        for (int i = 0; i < n; i++)
        {

            difference[i] = montgomery((long)r * (minuend[i] - subtrahend[i]), q, qInverse);

        }

    }

    /******************************************************************************************************************************************************************************************************************************
     * Description:	Polynomial Subtraction for Provably-Secure qTESLA Security Category-1 and Security Category-3
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

            difference[differenceOffset + i] = barrett(minuend[minuendOffset + i] - subtrahend[subtrahendOffset + i], q, barrettMultiplication, barrettDivision);

        }

    }

    /******************************************************************************************************************************************************************************
     * Description:	Generation of Polynomial A for Heuristic qTESLA Security Category-1 and Security Category-3 (Option for Size or Speed)
     *
     * @param        A                                    Polynomial to be Generated
     * @param        seed                                Kappa-Bit Seed
     * @param        seedOffset                            Starting Point of the Kappa-Bit Seed
     * @param        n                                    Polynomial Degree
     * @param        q                                    Modulus
     * @param        qInverse
     * @param        qLogarithm                            q <= 2 ^ qLogarithm
     * @param        generatorA
     * @param        inverseNumberTheoreticTransform
     *
     * @return none
     ******************************************************************************************************************************************************************************/
    public static void polynomialUniform(int[] A, byte[] seed, int seedOffset, int n, int q, long qInverse, int qLogarithm, int generatorA, int inverseNumberTheoreticTransform)
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

        byte[] buffer = new byte[HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * generatorA];

        HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(
            buffer, 0, HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * generatorA,
            dualModeSampler++,
            seed, seedOffset, RANDOM
        );

        while (i < n)
        {

            if (position > (HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * numberOfBlock - Const.INT_SIZE / Const.BYTE_SIZE * numberOfByte))
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

            if (value1 < q && i < n)
            {

                A[i++] = montgomery((long)value1 * inverseNumberTheoreticTransform, q, qInverse);

            }

            if (value2 < q && i < n)
            {

                A[i++] = montgomery((long)value2 * inverseNumberTheoreticTransform, q, qInverse);

            }

            if (value3 < q && i < n)
            {

                A[i++] = montgomery((long)value3 * inverseNumberTheoreticTransform, q, qInverse);

            }

            if (value4 < q && i < n)
            {

                A[i++] = montgomery((long)value4 * inverseNumberTheoreticTransform, q, qInverse);

            }

        }

    }

    /**************************************************************************************************************************************************************************************
     * Description:	Generation of Polynomial A for Provably-Secure qTESLA Security Category-1 and Security Category-3
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

            if (position > (HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * numberOfBlock - Const.INT_SIZE / Const.BYTE_SIZE * numberOfByte))
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

                A[i++] = montgomeryP((long)value1 * inverseNumberTheoreticTransform, q, qInverse);

            }

            if (value2 < q && i < n * k)
            {

                A[i++] = montgomeryP((long)value2 * inverseNumberTheoreticTransform, q, qInverse);

            }

            if (value3 < q && i < n * k)
            {

                A[i++] = montgomeryP((long)value3 * inverseNumberTheoreticTransform, q, qInverse);

            }

            if (value4 < q && i < n * k)
            {

                A[i++] = montgomeryP((long)value4 * inverseNumberTheoreticTransform, q, qInverse);

            }

        }

    }

    /**************************************************************************************************************************************************************
     * Description:	Performs Sparse Polynomial Multiplication for A Value Needed During Message Signification for Heuristic qTESLA Security Category-1 and
     *				SecurityCategory-3 (Option for Size or Speed)
     *
     * @param        product                Product of Two Polynomials
     * @param        privateKey            Part of the Private Key
     * @param        positionList        List of Indices of Non-Zero Elements in C
     * @param        signList            List of Signs of Non-Zero Elements in C
     * @param        n                    Polynomial Degree
     * @param        h                    Number of Non-Zero Entries of Output Elements of Encryption
     *
     * @return none
     **************************************************************************************************************************************************************/
    public static void sparsePolynomialMultiplication16(int[] product, final short[] privateKey, final int[] positionList, final short[] signList, int n, int h)
    {

        int position;

        Arrays.fill(product, 0);

        for (int i = 0; i < h; i++)
        {

            position = positionList[i];

            for (int j = 0; j < position; j++)
            {

                product[j] -= signList[i] * privateKey[n + j - position];

            }

            for (int j = position; j < n; j++)
            {

                product[j] += signList[i] * privateKey[j - position];

            }

        }

    }

    /*****************************************************************************************************************************************************************************************************
     * Description:	Performs Sparse Polynomial Multiplication for A Value Needed During Message Signification for Provably-Secure qTESLA Security Category-1 and Category-3
     *
     * @param        product                Product of Two Polynomials
     * @param        productOffset        Starting Point of the Product of Two Polynomials
     * @param        privateKey            Part of the Private Key
     * @param        privateKeyOffset    Starting Point of the Private Key
     * @param        positionList        List of Indices of Non-Zero Elements in C
     * @param        signList            List of Signs of Non-Zero Elements in C
     * @param        n                    Polynomial Degree
     * @param        h                    Number of Non-Zero Entries of Output Elements of Encryption
     *
     * @return none
     ******************************************************************************************************************************************************************************************************/
    public static void sparsePolynomialMultiplication8(long[] product, int productOffset, final byte[] privateKey, int privateKeyOffset, final int[] positionList, final short[] signList, int n, int h)
    {

        int position;

        Arrays.fill(product, 0L);

        for (int i = 0; i < h; i++)
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

    /***********************************************************************************************************************************************************
     * Description:	Performs Sparse Polynomial Multiplication for A Value Needed During Message Signification for Heuristic qTESLA Security Category-1 and
     * 				Security Category-3 (Option for Size or Speed)
     *
     * @param        product                    Product of Two Polynomials
     * @param        publicKey                Part of the Public Key
     * @param        positionList            List of Indices of Non-Zero Elements in C
     * @param        signList                List of Signs of Non-Zero Elements in C
     * @param        n                        Polynomial Degree
     * @param        h                        Number of Non-Zero Entries of Output Elements of Encryption
     *
     * @return none
     ***********************************************************************************************************************************************************/
    public static void sparsePolynomialMultiplication32(int[] product, final int[] publicKey, final int[] positionList, final short[] signList, int n, int h)
    {

        int position;

        Arrays.fill(product, 0);

        for (int i = 0; i < h; i++)
        {

            position = positionList[i];

            for (int j = 0; j < position; j++)
            {

                product[j] -= signList[i] * publicKey[n + j - position];

            }

            for (int j = position; j < n; j++)
            {

                product[j] += signList[i] * publicKey[j - position];

            }

        }

    }

    /***********************************************************************************************************************************************************************************************************************************************************
     * Description:	Performs Sparse Polynomial Multiplication for A Value Needed During Message Signification for Provably-Secure qTESLA Security Category-1 and Security Category-3
     *
     * @param        product                    Product of Two Polynomials
     * @param        productOffset            Starting Point of the Product of Two Polynomials
     * @param        publicKey                Part of the Public Key
     * @param        publicKeyOffset            Starting Point of the Public Key
     * @param        positionList            List of Indices of Non-Zero Elements in C
     * @param        signList                List of Signs of Non-Zero Elements in C
     * @param        n                        Polynomial Degree
     * @param        h                        Number of Non-Zero Entries of Output Elements of Encryption
     * @param        q                        Modulus
     * @param        barrettMultiplication
     * @param        barrettDivision
     *
     * @return none
     ***********************************************************************************************************************************************************************************************************************************************************/
    public static void sparsePolynomialMultiplication32(long[] product, int productOffset, final int[] publicKey, int publicKeyOffset, final int[] positionList, final short[] signList, int n, int h, int q, int barrettMultiplication, int barrettDivision)
    {

        int position;

        Arrays.fill(product, 0L);

        for (int i = 0; i < h; i++)
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

        for (int i = 0; i < n; i++)
        {

            product[productOffset + i] = barrett(product[productOffset + i], q, barrettMultiplication, barrettDivision);

        }

    }

}