package org.bouncycastle.pqc.crypto.ntruplus;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Implementation of the NTRU+ asymmetric key pair generator following the NTRU+ KEM specifications.
 * <p>
 * This generator produces {@link NTRUPlusPublicKeyParameters} and {@link NTRUPlusPrivateKeyParameters}
 * based on the chosen NTRU+ algorithm parameters. The implementation follows the specification
 * defined in the official NTRU+ documentation and reference implementation.
 * </p>
 * <p>
 * NTRU+ is a key encapsulation mechanism (KEM) and public key encryption (PKE) scheme based on
 * structured lattices. It was selected as a final algorithm in the Korean Post-Quantum Cryptography
 * Competition (KpqC).
 * </p>
 *
 * <p>References:</p>
 * <ul>
 *   <li><a href="https://sites.google.com/view/ntruplus/home">NTRU+ Official Website</a></li>
 *   <li><a href="https://github.com/ntruplus/ntruplus">NTRU+ Reference Implementation (C)</a></li>
 *   <li><a href="https://drive.google.com/file/d/1jEECOq-pD1mdgu-9MPFkucCaeK11C4Bz/view?usp=sharing">NTRU+ Submission Document (KpqC Round 2)</a></li>
 * </ul>
 */
public class NTRUPlusKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private NTRUPlusParameters params;
    private SecureRandom random;

    @Override
    public void init(KeyGenerationParameters param)
    {
        this.params = ((NTRUPlusKeyGenerationParameters)param).getParameters();
        this.random = param.getRandom();
    }

    @Override
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        byte[] pk = new byte[params.getPublicKeyBytes()];
        byte[] sk = new byte[params.getSecretKeyBytes()];
        NTRUPlusEngine engine = new NTRUPlusEngine(params);
        byte[] coins = new byte[NTRUPlusEngine.SSBytes]; // NTRUPLUS_SYMBYTES

        int n = params.getN();
        // Create polynomial objects
        short[] f = new short[n];
        short[] finv = new short[n];
        short[] g = new short[n];
        short[] ginv = new short[n];

        // Generate f and finv (retry if f is not invertible)
        boolean fInvertible;
        do
        {
            // Generate random bytes for the seed
            random.nextBytes(coins);
            fInvertible = (engine.genf_derand(f, finv, coins) == 0);
        }
        while (!fInvertible);

        // Generate g and ginv (retry if g is not invertible)
        boolean gInvertible;
        do
        {
            // Generate new random bytes for the seed
            random.nextBytes(coins);
            gInvertible = (engine.geng_derand(g, ginv, coins) == 0);
        }
        while (!gInvertible);

        // Generate the actual key pair using the derived polynomials
        engine.crypto_kem_keypair_derand(pk, sk, f, finv, g, ginv);
        return new AsymmetricCipherKeyPair(new NTRUPlusPublicKeyParameters(params, pk), new NTRUPlusPrivateKeyParameters(params, sk));
    }
}
