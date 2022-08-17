package org.bouncycastle.pqc.crypto.sphincsplus;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class SPHINCSPlusKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;
    private SPHINCSPlusParameters parameters;

    public void init(KeyGenerationParameters param)
    {
        random = param.getRandom();
        parameters = ((SPHINCSPlusKeyGenerationParameters)param).getParameters();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        SPHINCSPlusEngine engine = parameters.getEngine();
        byte[] pkSeed;
        SK sk;

        if (engine instanceof SPHINCSPlusEngine.HarakaSEngine)
        {
            // required to pass kat tests
            byte[] tmparray = sec_rand(engine.N * 3);
            byte[] skseed = new byte[engine.N];
            byte[] skprf = new byte[engine.N];
            pkSeed = new byte[engine.N];
            System.arraycopy(tmparray, 0, skseed, 0, engine.N);
            System.arraycopy(tmparray, engine.N, skprf, 0, engine.N);
            System.arraycopy(tmparray, engine.N << 1, pkSeed, 0, engine.N);
            sk = new SK(skseed, skprf);
        }
        else
        {
            sk = new SK(sec_rand(engine.N), sec_rand(engine.N));
            pkSeed = sec_rand(engine.N);
        }

        engine.init(pkSeed);

        // TODO
        PK pk = new PK(pkSeed, new HT(engine, sk.seed, pkSeed).htPubKey);

        return new AsymmetricCipherKeyPair(new SPHINCSPlusPublicKeyParameters(parameters, pk),
            new SPHINCSPlusPrivateKeyParameters(parameters, sk, pk));
    }

    private byte[] sec_rand(int n)
    {
        byte[] rv = new byte[n];

        random.nextBytes(rv);

        return rv;
    }
}
