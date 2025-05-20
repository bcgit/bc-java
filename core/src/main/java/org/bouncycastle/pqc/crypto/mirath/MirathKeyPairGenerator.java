package org.bouncycastle.pqc.crypto.mirath;


import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;


public class MirathKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private MirathParameters p;
    private SecureRandom random;

    @Override
    public void init(KeyGenerationParameters param)
    {
        this.p = ((MirathKeyGenerationParameters)param).getParameters();
        this.random = param.getRandom();
    }

    @Override
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        byte[] pk = new byte[p.getPublicKeyBytes()];
        byte[] sk = new byte[p.getSecretKeyBytes()];
        MirathEngine engine = new MirathEngine(p);
        // Step 1 & 2: Generate seeds
        byte[] seedSk = new byte[p.getSecurityLevelBytes()];
        byte[] seedPk = new byte[p.getSecurityLevelBytes()];
        random.nextBytes(seedSk);
        random.nextBytes(seedPk);

        // Initialize matrices
        byte[] S = new byte[engine.ffSBytes];
        byte[] C = new byte[engine.ffCBytes];
        byte[] H = new byte[engine.ffHBytes];
        byte[] y = new byte[engine.ffYBytes];

        // Step 3 & 4: Expand matrices
        engine.mirathMatrixExpandSeedSecretMatrix(S, C, seedSk);
        engine.mirathMatrixExpandSeedPublicMatrix(H, seedPk, 0);

        // Step 5: Compute y
        engine.mirathMatrixComputeY(y, S, C, H);

        // Step 6 & 7: Build keys
        //unparsePublicKey
        System.arraycopy(seedPk, 0, pk, 0, p.getSecurityLevelBytes());
        System.arraycopy(y, 0, pk, p.getSecurityLevelBytes(), y.length);
        //unparseSecretKey
        System.arraycopy(seedSk, 0, sk, 0, p.getSecurityLevelBytes());
        System.arraycopy(seedPk, 0, sk, p.getSecurityLevelBytes(), p.getSecurityLevelBytes());

        return new AsymmetricCipherKeyPair(new MirathPublicKeyParameters(p, pk), new MirathPrivateKeyParameters(p, sk));
    }
}
