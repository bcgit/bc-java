package org.bouncycastle.pqc.crypto.qtesla;

final class Parameter
{

    /**
     * Dimension, (Dimension - 1) is the Polynomial Degree for Heuristic qTESLA Security Category-1
     */
    public static final int N_I = 512;

    /**
     * Dimension, (Dimension - 1) is the Polynomial Degree for Provably-Secure qTESLA Security Category-1
     */
    public static final int N_I_P = 1024;

    /**
     * Dimension, (Dimension - 1) is the Polynomial Degree for Heuristic qTESLA Security Category-3 (Option for Size)
     */
    public static final int N_III_SIZE = 1024;

    /**
     * Dimension, (Dimension - 1) is the Polynomial Degree for Heuristic qTESLA Security Category-3 (Option for Speed)
     */
    public static final int N_III_SPEED = 1024;

    /**
     * Dimension, (Dimension - 1) is the Polynomial Degree for Provably-Secure qTESLA Security Category-3
     */
    public static final int N_III_P = 2048;

    /**
     * N_LOGARITHM = LOGARITHM (N) / LOGARITHM (2) for Heuristic qTESLA Security Category-1
     */
    public static final int N_LOGARITHM_I = 9;

    /**
     * N_LOGARITHM = LOGARITHM (N) / LOGARITHM (2) for Provably-Secure qTESLA Security Category-1
     */
    public static final int N_LOGARITHM_I_P = 10;

    /**
     * N_LOGARITHM = LOGARITHM (N) / LOGARITHM (2) for Heuristic qTESLA Security Category-3 (Option for Size)
     */
    public static final int N_LOGARITHM_III_SIZE = 10;

    /**
     * N_LOGARITHM = LOGARITHM (N) / LOGARITHM (2) for Heuristic qTESLA Security Category-3 (Option for Speed)
     */
    public static final int N_LOGARITHM_III_SPEED = 10;

    /**
     * N_LOGARITHM = LOGARITHM (N) / LOGARITHM (2) for Provably-Secure qTESLA Security Category-3
     */
    public static final int N_LOGARITHM_III_P = 11;

    /**
     * Modulus for Heuristic qTESLA Security Category-1
     */
    public static final int Q_I = 4205569;

    /**
     * Modulus for Provably-Secure qTESLA Security Category-1
     */
    public static final int Q_I_P = 485978113;

    /**
     * Modulus for Heuristic qTESLA Security Category-3 (Option for Size)
     */
    public static final int Q_III_SIZE = 4206593;

    /**
     * Modulus for Heuristic qTESLA Security Category-3 (Option for Speed)
     */
    public static final int Q_III_SPEED = 8404993;

    /**
     * Modulus for Provably-Secure qTESLA Security Category-3
     */
    public static final int Q_III_P = 1129725953;

    /**
     * Q <= 2 ^ Q_LOGARITHM for Heuristic qTESLA Security Category-1
     */
    public static final int Q_LOGARITHM_I = 23;

    /**
     * Q <= 2 ^ Q_LOGARITHM for Provably-Secure qTESLA Security Category-1
     */
    public static final int Q_LOGARITHM_I_P = 29;

    /**
     * Q <= 2 ^ Q_LOGARITHM for Heuristic qTESLA Security Category-3 (Option for Size)
     */
    public static final int Q_LOGARITHM_III_SIZE = 23;

    /**
     * Q <= 2 ^ Q_LOGARITHM for Heuristic qTESLA Security Category-3 (Option for Speed)
     */
    public static final int Q_LOGARITHM_III_SPEED = 24;

    /**
     * Q <= 2 ^ Q_LOGARITHM for Provably-Secure qTESLA Security Category-3
     */
    public static final int Q_LOGARITHM_III_P = 31;

    public static final long Q_INVERSE_I = 3098553343L;
    public static final long Q_INVERSE_I_P = 3421990911L;
    public static final long Q_INVERSE_III_SIZE = 4148178943L;
    public static final long Q_INVERSE_III_SPEED = 4034936831L;
    public static final long Q_INVERSE_III_P = 861290495L;

    /**
     * B Determines the Interval the Randomness is Chosen in During Signing for Heuristic qTESLA Security Category-1
     */
    public static final int B_I = 1048575;

    /**
     * B Determines the Interval the Randomness is Chosen in During Signing for Provably-Secure qTESLA Security Category-1
     */
    public static final int B_I_P = 2097151;

    /**
     * B Determines the Interval the Randomness is Chosen in During Signing for Heuristic qTESLA Security Category-3 (Option for Size)
     */
    public static final int B_III_SIZE = 1048575;

    /**
     * B Determines the Interval the Randomness is Chosen in During Signing for Heuristic qTESLA Security Category-3 (Option for Speed)
     */
    public static final int B_III_SPEED = 2097151;

    /**
     * B Determines the Interval the Randomness is Chosen in During Signing for Provably-Secure qTESLA Security Category-3
     */
    public static final int B_III_P = 8388607;

    /**
     * B = 2 ^ B_BIT - 1 for Heuristic qTESLA Security Category-1
     */
    public static final int B_BIT_I = 20;

    /**
     * B = 2 ^ B_BIT - 1 for Provably-Secure qTESLA Security Category-1
     */
    public static final int B_BIT_I_P = 21;

    /**
     * B = 2 ^ B_BIT - 1 for Heuristic qTESLA Security Category-3 (Option for Size)
     */
    public static final int B_BIT_III_SIZE = 20;

    /**
     * B = 2 ^ B_BIT - 1 for Heuristic qTESLA Security Category-3 (Option for Speed)
     */
    public static final int B_BIT_III_SPEED = 21;

    /**
     * B = 2 ^ B_BIT - 1 for Provably-Secure qTESLA Security Category-3
     */
    public static final int B_BIT_III_P = 23;

    /**
     * Number of Ring-Learning-With-Errors Samples for Heuristic qTESLA Security Category-1
     */
    public static final int K_I = 1;

    /**
     * Number of Ring-Learning-With-Errors Samples for Provably-Secure qTESLA Security Category-1
     */
    public static final int K_I_P = 4;

    /**
     * Number of Ring-Learning-With-Errors Samples for Heuristic qTESLA Security Category-3 (Option for Size)
     */
    public static final int K_III_SIZE = 1;

    /**
     * Number of Ring-Learning-With-Errors Samples for Heuristic qTESLA Security Category-3 (Option for Speed)
     */
    public static final int K_III_SPEED = 1;

    /**
     * Number of Ring-Learning-With-Errors Samples for Provably-Secure qTESLA Security Category-3
     */
    public static final int K_III_P = 5;

    /**
     * Number of Non-Zero Entries of Output Elements of Encryption for Heuristic qTESLA Security Category-1
     */
    public static final int W_I = 30;

    /**
     * Number of Non-Zero Entries of Output Elements of Encryption for Provably-Secure qTESLA Security Category-1
     */
    public static final int W_I_P = 25;

    /**
     * Number of Non-Zero Entries of Output Elements of Encryption for Heuristic qTESLA Security Category-3 (Option for Size)
     */
    public static final int W_III_SIZE = 48;

    /**
     * Number of Non-Zero Entries of Output Elements of Encryption for Heuristic qTESLA Security Category-3 (Option for Speed)
     */
    public static final int W_III_SPEED = 48;

    /**
     * Number of Non-Zero Entries of Output Elements of Encryption for Provably-Secure qTESLA Security Category-3
     */
    public static final int W_III_P = 40;

    /**
     * Number of Rounded Bits for Heuristic qTESLA Security Category-1
     */
    public static final int D_I = 21;

    /**
     * Number of Rounded Bits for Provably-Secure qTESLA Security Category-1
     */
    public static final int D_I_P = 22;

    /**
     * Number of Rounded Bits for Heuristic qTESLA Security Category-3 (Option for Size)
     */
    public static final int D_III_SIZE = 21;

    /**
     * Number of Rounded Bits for Heuristic qTESLA Security Category-3 (Option for Speed)
     */
    public static final int D_III_SPEED = 22;

    /**
     * Number of Rounded Bits for Provably-Secure qTESLA Security Category-3
     */
    public static final int D_III_P = 24;

    /**
     * Bound in Checking Error Polynomial for Heuristic qTESLA Security Category-1
     */
    public static final int KEY_GENERATOR_BOUND_E_I = 1586;

    /**
     * Bound in Checking Error Polynomial for Provably-Secure qTESLA Security Category-1
     */
    public static final int KEY_GENERATOR_BOUND_E_I_P = 554;

    /**
     * Bound in Checking Error Polynomial for Heuristic qTESLA Security Category-3 (Option for Size)
     */
    public static final int KEY_GENERATOR_BOUND_E_III_SIZE = 910;

    /**
     * Bound in Checking Error Polynomial for Heuristic qTESLA Security Category-3 (Option for Speed)
     */
    public static final int KEY_GENERATOR_BOUND_E_III_SPEED = 1147;

    /**
     * Bound in Checking Error Polynomial for Provably-Secure qTESLA Security Category-3
     */
    public static final int KEY_GENERATOR_BOUND_E_III_P = 901;

    public static final int REJECTION_I = 1586;
    public static final int REJECTION_I_P = 554;
    public static final int REJECTION_III_SIZE = 910;
    public static final int REJECTION_III_SPEED = 1147;
    public static final int REJECTION_III_P = 901;

    /**
     * Bound in Checking Secret Polynomial for Heuristic qTESLA Security Category-1
     */
    public static final int KEY_GENERATOR_BOUND_S_I = 1586;

    /**
     * Bound in Checking Secret Polynomial for Provably-Secure qTESLA Security Category-1
     */
    public static final int KEY_GENERATOR_BOUND_S_I_P = 554;

    /**
     * Bound in Checking Secret Polynomial for Heuristic qTESLA Security Category-3 (Option for Size)
     */
    public static final int KEY_GENERATOR_BOUND_S_III_SIZE = 910;

    /**
     * Bound in Checking Secret Polynomial for Heuristic qTESLA Security Category-3 (Option for Speed)
     */
    public static final int KEY_GENERATOR_BOUND_S_III_SPEED = 1233;

    /**
     * Bound in Checking Secret Polynomial for Provably-Secure qTESLA Security Category-3
     */
    public static final int KEY_GENERATOR_BOUND_S_III_P = 901;

    public static final int U_I = 1586;
    public static final int U_I_P = 554;
    public static final int U_III_SIZE = 910;
    public static final int U_III_SPEED = 1233;
    public static final int U_III_P = 901;

    /**
     * Standard Deviation of Centered Discrete Gaussian Distribution for Heuristic qTESLA Security Category-1
     */
    public static final double SIGMA_I = 23.78;

    /**
     * Standard Deviation of Centered Discrete Gaussian Distribution for Provably-Secure qTESLA Security Category-1
     */
    public static final double SIGMA_I_P = 8.5;

    /**
     * Standard Deviation of Centered Discrete Gaussian Distribution for Heuristic qTESLA Security Category-3 (Option for Size)
     */
    public static final double SIGMA_III_SIZE = 8.49;

    /**
     * Standard Deviation of Centered Discrete Gaussian Distribution for Heuristic qTESLA Security Category-3 (Option for Speed)
     */
    public static final double SIGMA_III_SPEED = 10.2;

    /**
     * Standard Deviation of Centered Discrete Gaussian Distribution for Provably-Secure qTESLA Security Category-3
     */
    public static final double SIGMA_III_P = 8.5;

    public static final double SIGMA_E_I = 23.78;
    public static final double SIGMA_E_I_P = 8.5;
    public static final double SIGMA_E_III_SIZE = 8.49;
    public static final double SIGMA_E_III_SPEED = 10.2;
    public static final double SIGMA_E_III_P = 8.5;

    /**
     * XI = SIGMA * SQUARE_ROOT (2 * LOGARITHM (2) / LOGARITHM (e)) for Heuristic qTESLA Security Category-1
     */
    public static final double XI_I = 27.9988;

    /**
     * XI = SIGMA * SQUARE_ROOT (2 * LOGARITHM (2) / LOGARITHM (e)) for Provably-Secure qTESLA Security Category-1
     */
    public static final double XI_I_P = 10.0080;

    /**
     * XI = SIGMA * SQUARE_ROOT (2 * LOGARITHM (2) / LOGARITHM (e)) for Heuristic qTESLA Security Category-3 (Option for Size)
     */
    public static final double XI_III_SIZE = 9.9962;

    /**
     * XI = SIGMA * SQUARE_ROOT (2 * LOGARITHM (2) / LOGARITHM (e)) for Heuristic qTESLA Security Category-3 (Option for Speed)
     */
    public static final double XI_III_SPEED = 12.0096;

    /**
     * XI = SIGMA * SQUARE_ROOT (2 * LOGARITHM (2) / LOGARITHM (e)) for Provably-Secure qTESLA Security Category-3
     */
    public static final double XI_III_P = 10.0080;

    public static final int BARRETT_MULTIPLICATION_I = 1021;
    public static final int BARRETT_MULTIPLICATION_I_P = 1;
    public static final int BARRETT_MULTIPLICATION_III_SIZE = 1021;
    public static final int BARRETT_MULTIPLICATION_III_SPEED = 511;
    public static final int BARRETT_MULTIPLICATION_III_P = 15;

    public static final int BARRETT_DIVISION_I = 32;
    public static final int BARRETT_DIVISION_I_P = 29;
    public static final int BARRETT_DIVISION_III_SIZE = 32;
    public static final int BARRETT_DIVISION_III_SPEED = 32;
    public static final int BARRETT_DIVISION_III_P = 34;

    /**
     * The Number of Blocks Requested in the First Extendable-Output Function Call
     * for Heuristic qTESLA Security Category-1
     */
    public static final int GENERATOR_A_I = 19;

    /**
     * The Number of Blocks Requested in the First Extendable-Output Function Call
     * for Provably-Secure qTESLA Security Category-1
     */
    public static final int GENERATOR_A_I_P = 108;

    /**
     * The Number of Blocks Requested in the First Extendable-Output Function Call
     * for Provably-Secure qTESLA Security Category-3 (Option for Size)
     */
    public static final int GENERATOR_A_III_SIZE = 38;

    /**
     * The Number of Blocks Requested in the First Extendable-Output Function Call
     * for Provably-Secure qTESLA Security Category-3 (Option for Speed)
     */
    public static final int GENERATOR_A_III_SPEED = 38;

    /**
     * The Number of Blocks Requested in the First Extendable-Output Function Call
     * for Provably-Secure qTESLA Security Category-3
     */
    public static final int GENERATOR_A_III_P = 180;

    public static final int INVERSE_NUMBER_THEORETIC_TRANSFORM_I = 113307;
    public static final int INVERSE_NUMBER_THEORETIC_TRANSFORM_I_P = 472064468;
    public static final int INVERSE_NUMBER_THEORETIC_TRANSFORM_III_SIZE = 1217638;
    public static final int INVERSE_NUMBER_THEORETIC_TRANSFORM_III_SPEED = 237839;
    public static final int INVERSE_NUMBER_THEORETIC_TRANSFORM_III_P = 851423148;

}
