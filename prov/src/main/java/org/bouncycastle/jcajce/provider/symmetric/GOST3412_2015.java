package org.bouncycastle.jcajce.provider.symmetric;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.engines.GOST3412_2015Engine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.modes.*;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseStreamCipher;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;


public class GOST3412_2015 {


    public static class ECB
        extends BaseBlockCipher {
        public ECB() {
            super(new GOST3412_2015Engine());
        }
    }

    public static class CBC
        extends BaseBlockCipher {
        public CBC() {
            super(new G3412CBCBlockCipher(new GOST3412_2015Engine()), 128);
        }
    }

    public static class GCFB
        extends BaseBlockCipher {
        public GCFB() {
            super(new BufferedBlockCipher(new G3412CFBBlockCipher(new GOST3412_2015Engine())), 128);
        }
    }

    public static class GCFB_STREAM
        extends BaseStreamCipher {
        public GCFB_STREAM() {
            super(new G3412CFBStreamBlockCipher(new GOST3412_2015Engine()), 128);
        }
    }

    public static class OFB extends BaseBlockCipher {
        public OFB() {
            super(new BufferedBlockCipher(new G3412OFBBlockCipher(new GOST3412_2015Engine())), 128);
        }

    }

    public static class CTR extends BaseBlockCipher {
        public CTR() {
            super(new BufferedBlockCipher(new G3412CTRBlockCipher(new GOST3412_2015Engine(), 128)), 128);
        }

    }


//    public static class GostWrap
//        extends BaseWrapCipher
//    {
//        public GostWrap()
//        {
//            super(new GOST28147WrapEngine());
//        }
//    }

    /**
     * GOST3412 2015 CMAC( OMAC1)
     */
    public static class Mac
        extends CMac {
        public Mac() {
            super(new GOST3412_2015Engine());
        }
    }


    public static class KeyGen
        extends BaseKeyGenerator {
        public KeyGen() {
            this(256);
        }

        public KeyGen(int keySize) {
            super("GOST3412_2015", keySize, new CipherKeyGenerator());
        }
    }

    public static class Mappings
        extends AlgorithmProvider {
        private static final String PREFIX = GOST3412_2015.class.getName();

        public Mappings() {
        }

        public void configure(ConfigurableProvider provider) {
            provider.addAlgorithm("Cipher.GOST3412_2015", PREFIX + "$ECB");
            provider.addAlgorithm("Alg.Alias.Cipher.GOST3412_2015", "GOST3412_2015");
            provider.addAlgorithm("Alg.Alias.Cipher.GOST3412_2015_CFB", PREFIX + "$GCFB");
            provider.addAlgorithm("Alg.Alias.Cipher.GOST3412_2015_OFB", PREFIX + "$OFB");
            provider.addAlgorithm("Alg.Alias.Cipher.GOST3412_2015_CTR", PREFIX + "$CTR");

//            provider.addAlgorithm("Cipher." + CryptoProObjectIdentifiers.gostR28147_gcfb, PREFIX + "$GCFB");

            provider.addAlgorithm("KeyGenerator.GOST3412_2015", PREFIX + "$KeyGen");
            provider.addAlgorithm("Alg.Alias.KeyGenerator.GOST", "GOST3412_2015");
            provider.addAlgorithm("Alg.Alias.KeyGenerator.GOST3412_2015", "GOST3412_2015");


//            provider.addAlgorithm("Cipher." + CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_KeyWrap, PREFIX + "$CryptoProWrap");
//            provider.addAlgorithm("Cipher." + CryptoProObjectIdentifiers.id_Gost28147_89_None_KeyWrap, PREFIX + "$GostWrap");

            provider.addAlgorithm("Mac.GOST3412MAC", PREFIX + "$Mac");
            provider.addAlgorithm("Alg.Alias.Mac.GOST3412_2015", "GOST3412MAC");
        }
    }


}
