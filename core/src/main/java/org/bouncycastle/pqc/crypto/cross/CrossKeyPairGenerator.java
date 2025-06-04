package org.bouncycastle.pqc.crypto.cross;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class CrossKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private CrossParameters params;
    private CsprngSecureRandom random;

    public void init(KeyGenerationParameters param)
    {
        this.params = ((CrossKeyGenerationParameters)param).getParameters();
        this.random = (CsprngSecureRandom)param.getRandom();
    }

    @Override
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        // Step 1: Generate random seed for secret key
        byte[] seedSk = new byte[params.getKeypairSeedLengthBytes()];
        random.init(params.category, new byte[2]);
        random.nextBytes(seedSk);

        // Step 2: Initialize CSPRNG for key generation
        int dscCsprngSeedSk = (3 * params.getT() + 1); // CSPRNG_DOMAIN_SEP_CONST = 0
        CrossEngine engine = new CrossEngine(params.getSecMarginLambda());
        engine.init(seedSk, seedSk.length, dscCsprngSeedSk);

        // Step 3: Generate seeds for error vector and public key
        byte[][] seedESeedPk = new byte[2][params.getKeypairSeedLengthBytes()];
        engine.randomBytes(seedESeedPk[0], params.getKeypairSeedLengthBytes());
        engine.randomBytes(seedESeedPk[1], params.getKeypairSeedLengthBytes());
        byte[] seedPk = seedESeedPk[1].clone();

        // Step 4: Expand public key matrices
        if (params.getP() == 127)
        { // RSDP
            byte[][] V_tr = new byte[params.getK()][params.getN() - params.getK()];
            engine.expandPk(params, V_tr, seedPk);

            // Step 5: Generate error vector
            int dscCsprngSeedE = (3 * params.getT() + 3);
            engine.init(seedESeedPk[0], seedESeedPk[0].length, dscCsprngSeedE);
            byte[] e_bar = new byte[params.getN()];
            engine.csprngFzVec(e_bar, params);

            // Step 6: Compute syndrome
            byte[] s = new byte[params.getN() - params.getK()];
            CrossEngine.restrVecByFpMatrix(s, e_bar, V_tr, params);
            CrossEngine.fpDzNormSynd(s, params);
            byte[] packedS = new byte[params.getDenselyPackedFpSynSize()];
            CrossEngine.packFpSyn(packedS, s, params);

            return new AsymmetricCipherKeyPair(
                new CrossPublicKeyParameters(params, Arrays.concatenate(seedPk, packedS)),
                new CrossPrivateKeyParameters(params, seedSk)
            );
        }
        else if (params.getP() == 509)
        { // RSDPG
            short[][] V_tr = new short[params.getK()][params.getN() - params.getK()];
            byte[][] W_mat = new byte[params.getM()][params.getN() - params.getM()];
            engine.expandPk(params, V_tr, W_mat, seedPk);

            // Step 5: Generate error vector
            int dscCsprngSeedE = (3 * params.getT() + 3);
            engine.init(seedESeedPk[0], seedESeedPk[0].length, dscCsprngSeedE);
            byte[] e_G_bar = new byte[params.getM()];
            engine.csprngFzInfW(e_G_bar, params);
            byte[] e_bar = new byte[params.getN()];
            CrossEngine.fzInfWByFzMatrix(e_bar, e_G_bar, W_mat, params);
            CrossEngine.fzDzNormN(e_bar);

            // Step 6: Compute syndrome
            short[] s = new short[params.getN() - params.getK()];
            CrossEngine.restrVecByFpMatrix(s, e_bar, V_tr, params);
            // For P=509, normalization is identity so we skip explicit call
            byte[] packedS = new byte[params.getDenselyPackedFpSynSize()];
            byte[] bs = new byte[s.length << 1];
            Pack.shortToLittleEndian(s, 0, s.length, bs, 0);
            CrossEngine.packFpSyn(packedS, bs, params);

            return new AsymmetricCipherKeyPair(
                new CrossPublicKeyParameters(params, Arrays.concatenate(seedPk, packedS)),
                new CrossPrivateKeyParameters(params, seedSk)
            );
        }
        return null;
    }

}
