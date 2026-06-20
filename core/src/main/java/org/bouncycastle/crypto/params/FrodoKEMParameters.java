package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.KEMParameters;
import org.bouncycastle.crypto.kems.frodo.FrodoKEMEngine;

/**
 * Parameter sets for FrodoKEM as standardised in ISO/IEC 18033-2:2006/Amd 2:2026, Clause 14.
 * <p>
 * For each of the two standardised security levels (976 and 1344) there are, in both a SHAKE128 and
 * an AES-128 matrix-generation variant:
 * <ul>
 *   <li>the salted "FrodoKEM" variant ({@link #frodokem976shake}, {@link #frodokem1344shake},
 *       {@link #frodokem976aes}, {@link #frodokem1344aes}), which applies the Salted Fujisaki-Okamoto
 *       transform for tight multi-ciphertext security; and</li>
 *   <li>the ephemeral "eFrodoKEM" variant ({@link #efrodokem976shake}, {@link #efrodokem1344shake},
 *       {@link #efrodokem976aes}, {@link #efrodokem1344aes}), which omits the salt and must only be
 *       used where fewer than 2^8 ciphertexts are produced per public key.</li>
 * </ul>
 */
public class FrodoKEMParameters
    implements KEMParameters
{
    // salted FrodoKEM (the standard variant) - SHAKE128 matrix generation
    public static final FrodoKEMParameters frodokem976shake = new FrodoKEMParameters("frodokem976shake", 976, 16, 3, true, false);
    public static final FrodoKEMParameters frodokem1344shake = new FrodoKEMParameters("frodokem1344shake", 1344, 16, 4, true, false);

    // ephemeral eFrodoKEM (unsalted) - SHAKE128 matrix generation
    public static final FrodoKEMParameters efrodokem976shake = new FrodoKEMParameters("efrodokem976shake", 976, 16, 3, false, false);
    public static final FrodoKEMParameters efrodokem1344shake = new FrodoKEMParameters("efrodokem1344shake", 1344, 16, 4, false, false);

    // salted FrodoKEM - AES-128 matrix generation
    public static final FrodoKEMParameters frodokem976aes = new FrodoKEMParameters("frodokem976aes", 976, 16, 3, true, true);
    public static final FrodoKEMParameters frodokem1344aes = new FrodoKEMParameters("frodokem1344aes", 1344, 16, 4, true, true);

    // ephemeral eFrodoKEM (unsalted) - AES-128 matrix generation
    public static final FrodoKEMParameters efrodokem976aes = new FrodoKEMParameters("efrodokem976aes", 976, 16, 3, false, true);
    public static final FrodoKEMParameters efrodokem1344aes = new FrodoKEMParameters("efrodokem1344aes", 1344, 16, 4, false, true);

    private final String name;
    private final int n;
    private final int D;
    private final int B;
    private final boolean salted;
    private final boolean aes;
    private final int defaultKeySize;

    private FrodoKEMParameters(String name, int n, int D, int B, boolean salted, boolean aes)
    {
        this.name = name;
        this.n = n;
        this.D = D;
        this.B = B;
        this.salted = salted;
        this.aes = aes;
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

    public boolean isAes()
    {
        return aes;
    }
}
