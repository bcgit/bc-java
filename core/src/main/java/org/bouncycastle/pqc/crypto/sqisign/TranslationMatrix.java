package org.bouncycastle.pqc.crypto.sqisign;


/**
 * 2×2 Fp² matrix used for the "action by translation" step of theta gluing.
 * Layout matches C {@code translation_matrix_t}: (g00, g01, g10, g11).
 */
final class TranslationMatrix
{
    public final Fp2 g00;
    public final Fp2 g01;
    public final Fp2 g10;
    public final Fp2 g11;

    public TranslationMatrix()
    {
        this.g00 = Fp2.zero();
        this.g01 = Fp2.zero();
        this.g10 = Fp2.zero();
        this.g11 = Fp2.zero();
    }
}
