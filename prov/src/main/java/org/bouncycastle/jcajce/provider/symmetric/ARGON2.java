package org.bouncycastle.jcajce.provider.symmetric;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseSecretKeyFactory;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;
import org.bouncycastle.jcajce.spec.Argon2KeySpec;

public class ARGON2
{
    private ARGON2()
    {

    }

    public static class BaseArgon2
        extends BaseSecretKeyFactory
    {
        public BaseArgon2(String name)
        {
            super(name, null);
        }

        protected SecretKey engineGenerateSecret(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            if (keySpec instanceof Argon2KeySpec)
            {
                Argon2KeySpec argonSpec = (Argon2KeySpec)keySpec;

                if (argonSpec.getSalt() == null)
                {
                    throw new IllegalArgumentException("Salt S must be provided.");
                }
                if (argonSpec.getKeyLength() <= 0)
                {
                    throw new InvalidKeySpecException("positive key length required: "
                        + argonSpec.getKeyLength());
                }
                if (argonSpec.getPassword() == null || argonSpec.getPassword().length == 0)
                {
                    throw new IllegalArgumentException("password empty");
                }

                Argon2Parameters.Builder builder = new Argon2Parameters.Builder(argonSpec.getType())
                    .withVersion(argonSpec.getVersion())
                    .withSalt(argonSpec.getSalt())
                    .withIterations(argonSpec.getIterations())
                    .withMemoryAsKB(argonSpec.getMemory())
                    .withParallelism(argonSpec.getParallelism());

                if (argonSpec.getSecret() != null)
                {
                    builder.withSecret(argonSpec.getSecret());
                }
                if (argonSpec.getAdditional() != null)
                {
                    builder.withAdditional(argonSpec.getAdditional());
                }

                Argon2BytesGenerator gen = new Argon2BytesGenerator();

                gen.init(builder.build());

                byte[] keyBytes = new byte[argonSpec.getKeyLength() / 8];

                gen.generateBytes(argonSpec.getPassword(), keyBytes);

                CipherParameters param = new KeyParameter(keyBytes);

                return new BCPBEKey(this.algName, param);
            }

            throw new InvalidKeySpecException("Invalid KeySpec");
        }
    }

    public static class Argon2
        extends BaseArgon2
    {
        public Argon2()
        {
            super("ARGON2");
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = ARGON2.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("SecretKeyFactory.ARGON2", PREFIX + "$Argon2");
        }
    }
}
