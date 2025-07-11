package org.bouncycastle.pqc.crypto.cross;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Implementation of the Cross asymmetric key pair generator following the Cross signature scheme specifications.
 * <p>
 * This generator produces {@link CrossPublicKeyParameters} and {@link CrossPrivateKeyParameters} based on the
 * Cross algorithm parameters. The implementation follows the specification defined in the official Cross
 * documentation and reference implementation.
 * </p>
 *
 * <p>References:</p>
 * <ul>
 *   <li><a href="https://https://cross-crypto.com/">Cross Official Website</a></li>
 *   <li><a href="https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/round-2/spec-files/cross-spec-round2-web.pdf">Cross Specification Document</a></li>
 *   <li><a href="https://github.com/CROSS-signature">Cross Reference Implementation (C)</a></li>
 * </ul>
 */
public class CrossKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private CrossParameters params;
    private SecureRandom random;

    public void init(KeyGenerationParameters param)
    {
        this.params = ((CrossKeyGenerationParameters)param).getParameters();
        this.random = param.getRandom();
    }

    @Override
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        int k = params.getK();
        int n = params.getN();
        int keypairSeedLength = params.getKeypairSeedLengthBytes();
        byte[] seedSk = new byte[params.getKeypairSeedLengthBytes()];
        byte[] pk = new byte[params.getDenselyPackedFpSynSize() + params.getKeypairSeedLengthBytes()];
        byte[] e_bar = new byte[n];
        random.nextBytes(seedSk);

        CrossEngine engine = new CrossEngine(params);
        engine.init(seedSk, seedSk.length, 3 * params.getT() + 1);

        byte[] seedESeedPk = new byte[keypairSeedLength];
        engine.randomBytes(seedESeedPk, params.getKeypairSeedLengthBytes());
        engine.randomBytes(pk, params.getKeypairSeedLengthBytes());
        engine.init(seedESeedPk, seedESeedPk.length, 3 * params.getT() + 3);
        if (params.rsdp)
        {
            byte[][] V_tr = new byte[k][n - k];
            byte[] s = new byte[n - k];
            engine.csprngFVec(e_bar, params.getZ(), n, params.getBitsNFzCtRng());
            engine.expandPk(V_tr, pk);
            CrossEngine.restrVecByFpMatrix(s, e_bar, V_tr, n, k, n - k);
            CrossEngine.fDzNorm(s, s.length);
            Utils.genericPack7Bit(pk, keypairSeedLength, s, s.length);
        }
        else
        {
            int m = params.getM();
            short[][] V_tr = new short[k][n - k];
            byte[][] W_mat = new byte[m][n - m];
            byte[] e_G_bar = new byte[m];
            short[] s = new short[n - k];
            engine.csprngFVec(e_G_bar, params.getZ(), m, params.getBitsMFzCtRng());
            engine.expandPk(V_tr, W_mat, pk);
            CrossEngine.fzInfWByFzMatrix(e_bar, e_G_bar, W_mat, m, n - m);
            //CrossEngine.fDzNorm(e_bar, e_bar.length);
            CrossEngine.restrVecByFpMatrix(s, e_bar, V_tr, n, k, n - k);
            Utils.genericPack9Bit(pk, keypairSeedLength, s, s.length);
        }
        return new AsymmetricCipherKeyPair(new CrossPublicKeyParameters(params, pk), new CrossPrivateKeyParameters(params, seedSk));
    }

}
