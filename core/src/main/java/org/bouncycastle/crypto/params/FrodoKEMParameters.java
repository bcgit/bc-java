package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.KEMParameters;
import org.bouncycastle.crypto.kems.frodo.FrodoKEMEngine;

/**
 * Parameter sets for FrodoKEM as standardised in ISO/IEC 18033-2:2006/Amd 2:2026, Clause 14.
 * <p>
 * Two variants are provided for each of the two standardised security levels (976 and 1344), using
 * SHAKE128 for the generation of the matrix A:
 * <ul>
 *   <li>the salted "FrodoKEM" variant ({@link #frodokem976shake}, {@link #frodokem1344shake}), which
 *       applies the Salted Fujisaki-Okamoto transform for tight multi-ciphertext security; and</li>
 *   <li>the ephemeral "eFrodoKEM" variant ({@link #efrodokem976shake}, {@link #efrodokem1344shake}),
 *       which omits the salt and must only be used where fewer than 2^8 ciphertexts are produced per
 *       public key.</li>
 * </ul>
 */
public class FrodoKEMParameters
    implements KEMParameters
{
    // salted FrodoKEM (the standard variant)
    public static final FrodoKEMParameters frodokem976shake = new FrodoKEMParameters("frodokem976shake", 976, 16, 3, true);
    public static final FrodoKEMParameters frodokem1344shake = new FrodoKEMParameters("frodokem1344shake", 1344, 16, 4, true);

    // ephemeral eFrodoKEM (unsalted)
    public static final FrodoKEMParameters efrodokem976shake = new FrodoKEMParameters("efrodokem976shake", 976, 16, 3, false);
    public static final FrodoKEMParameters efrodokem1344shake = new FrodoKEMParameters("efrodokem1344shake", 1344, 16, 4, false);

    private final String name;
    private final int n;
    private final int D;
    private final int B;
    private final boolean salted;
    private final int defaultKeySize;

    private FrodoKEMParameters(String name, int n, int D, int B, boolean salted)
    {
        this.name = name;
        this.n = n;
        this.D = D;
        this.B = B;
        this.salted = salted;
        this.defaultKeySize = B * FrodoKEMEngine.nbar * FrodoKEMEngine.nbar;
    }

    public String getName()
    {
        return name;
    }

    public int getSessionKeySize()
    {
        return defaultKeySize;
    }

    public int getEncapsulationLength()
    {
        return FrodoKEMEngine.getInstance(this).getCipherTextSize();
    }

    public int getN()
    {
        return n;
    }

    public int getD()
    {
        return D;
    }

    public int getB()
    {
        return B;
    }

    public boolean isSalted()
    {
        return salted;
    }
}
