package org.bouncycastle.jcajce.provider.symmetric;

import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.engines.AsconAEAD128;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

/**
 * Ascon-AEAD128 (NIST SP 800-232) as a JCA Cipher: a 128 bit key, a 128 bit nonce (generated
 * if none is given on an encryption init) and a 128 bit tag. The nonce is carried as an
 * IvParameterSpec or through the ASCON-AEAD128 AlgorithmParameters.
 */
public final class Ascon
{
    private Ascon()
    {
    }

    public static class AEAD128
        extends BaseBlockCipher
    {
        public AEAD128()
        {
            super(new AsconAEAD128(), true, 16);
        }
    }

    public static class KeyGenAEAD128
        extends BaseKeyGenerator
    {
        public KeyGenAEAD128()
        {
            super("Ascon-AEAD128", 128, new CipherKeyGenerator());
        }
    }

    public static class AlgParamsAEAD128
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Ascon-AEAD128 IV";
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = Ascon.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("Cipher.ASCON-AEAD128", PREFIX + "$AEAD128");
            provider.addAlgorithm("KeyGenerator.ASCON-AEAD128", PREFIX + "$KeyGenAEAD128");
            provider.addAlgorithm("AlgorithmParameters.ASCON-AEAD128", PREFIX + "$AlgParamsAEAD128");
        }
    }
}
