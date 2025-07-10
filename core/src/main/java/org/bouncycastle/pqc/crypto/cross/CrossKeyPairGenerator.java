package org.bouncycastle.pqc.crypto.cross;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

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

        random.nextBytes(seedSk);

        CrossEngine engine = new CrossEngine(params);
        engine.init(seedSk, seedSk.length, 3 * params.getT() + 1);

        byte[] seedESeedPk = new byte[keypairSeedLength];
        engine.randomBytes(seedESeedPk, params.getKeypairSeedLengthBytes());
        engine.randomBytes(pk, params.getKeypairSeedLengthBytes());

        if (params.rsdp)
        {
            byte[][] V_tr = new byte[k][n - k];
            byte[] e_bar = new byte[n];
            byte[] s = new byte[n - k];
            engine.expandPk(params, V_tr, pk);
            engine.init(seedESeedPk, seedESeedPk.length, 3 * params.getT() + 3);
            engine.csprngFVec(e_bar, params.getZ(), n, Utils.roundUp(params.getBitsNFzCtRng(), 8) >>> 3);
            CrossEngine.restrVecByFpMatrix(s, e_bar, V_tr, params);
            CrossEngine.fDzNorm(s, s.length);
            Utils.genericPack7Bit(pk, keypairSeedLength, s, s.length);
        }
        else
        {
            int m = params.getM();
            short[][] V_tr = new short[k][n - k];
            byte[][] W_mat = new byte[m][n - m];
            byte[] e_G_bar = new byte[m];
            byte[] e_bar = new byte[n];
            short[] s = new short[n - k];
            engine.expandPk(params, V_tr, W_mat, pk);
            engine.init(seedESeedPk, seedESeedPk.length, 3 * params.getT() + 3);
            engine.csprngFVec(e_G_bar, params.getZ(), m, Utils.roundUp(params.getBitsMFzCtRng(), 8) >>> 3);
            CrossEngine.fzInfWByFzMatrix(e_bar, e_G_bar, W_mat, params);
            CrossEngine.fDzNorm(e_bar, e_bar.length);
            CrossEngine.restrVecByFpMatrix(s, e_bar, V_tr, params);
            Utils.genericPack9Bit(pk, keypairSeedLength, s, s.length);
        }
        return new AsymmetricCipherKeyPair(new CrossPublicKeyParameters(params, pk), new CrossPrivateKeyParameters(params, seedSk));
    }

}
