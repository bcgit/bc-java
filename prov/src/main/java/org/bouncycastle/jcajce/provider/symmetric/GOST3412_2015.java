package org.bouncycastle.jcajce.provider.symmetric;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.engines.CryptoProWrapEngine;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.engines.GOST28147WrapEngine;
import org.bouncycastle.crypto.engines.GOST3412_2015Engine;
import org.bouncycastle.crypto.macs.GOST3412_2015Mac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.GCFBBlockCipher;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.*;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;


public class GOST3412_2015 {


    public static class ECB
        extends BaseBlockCipher
    {
        public ECB()
        {
            super(new GOST3412_2015Engine());
        }
    }

    public static class CBC
        extends BaseBlockCipher
    {
        public CBC()
        {
            super(new CBCBlockCipher(new GOST3412_2015Engine()), 128);
        }
    }

    public static class GCFB
        extends BaseBlockCipher
    {
        public GCFB()
        {
            super(new BufferedBlockCipher(new GCFBBlockCipher(new GOST28147Engine())), 128);
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
     * GOST3412 2015
     */
    public static class Mac
        extends BaseMac
    {
        public Mac()
        {
            super(new GOST3412_2015Mac());
        }
    }


    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            this(256);
        }

        public KeyGen(int keySize)
        {
            super("GOST3412_2015", keySize, new CipherKeyGenerator());
        }
    }

//    public static class AlgParamGen
//        extends BaseAlgorithmParameterGenerator
//    {
//        byte[] iv = new byte[8];
//        byte[] sBox = GOST28147Engine.getSBox("E-A");
//
//        protected void engineInit(
//            AlgorithmParameterSpec genParamSpec,
//            SecureRandom random)
//            throws InvalidAlgorithmParameterException
//        {
//            if (genParamSpec instanceof GOST28147ParameterSpec)
//            {
//                this.sBox = ((GOST28147ParameterSpec)genParamSpec).getSBox();
//            }
//            else
//            {
//                throw new InvalidAlgorithmParameterException("parameter spec not supported");
//            }
//        }
//
//        protected AlgorithmParameters engineGenerateParameters()
//        {
//            if (random == null)
//            {
//                random = new SecureRandom();
//            }
//
//            random.nextBytes(iv);
//
//            AlgorithmParameters params;
//
//            try
//            {
//                params = createParametersInstance("GOST28147");
//                params.init(new GOST28147ParameterSpec(sBox, iv));
//            }
//            catch (Exception e)
//            {
//                throw new RuntimeException(e.getMessage());
//            }
//
//            return params;
//        }
//    }
//

    public static class Mappings
        extends AlgorithmProvider {
        private static final String PREFIX = GOST3412_2015.class.getName();

        public Mappings() {
        }

        public void configure(ConfigurableProvider provider) {
            provider.addAlgorithm("Cipher.GOST3412_2015", PREFIX + "$ECB");
            provider.addAlgorithm("Alg.Alias.Cipher.GOST", "GOST3412_2015");
            provider.addAlgorithm("Alg.Alias.Cipher.GOST3412_2015", "GOST3412_2015");
            provider.addAlgorithm("Cipher." + CryptoProObjectIdentifiers.gostR28147_gcfb, PREFIX + "$GCFB");

            provider.addAlgorithm("KeyGenerator.GOST3412_2015", PREFIX + "$KeyGen");
            provider.addAlgorithm("Alg.Alias.KeyGenerator.GOST", "GOST3412_2015");
            provider.addAlgorithm("Alg.Alias.KeyGenerator.GOST3412_2015", "GOST3412_2015");
            provider.addAlgorithm("Alg.Alias.KeyGenerator." + CryptoProObjectIdentifiers.gostR28147_gcfb, "GOST3412_2015");

            provider.addAlgorithm("AlgorithmParameters." + "GOST3412_2015", PREFIX + "$AlgParams");
            provider.addAlgorithm("AlgorithmParameterGenerator." + "GOST3412_2015", PREFIX + "$AlgParamGen");

            provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + CryptoProObjectIdentifiers.gostR28147_gcfb, "GOST3412_2015");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + CryptoProObjectIdentifiers.gostR28147_gcfb, "GOST3412_2015");

            provider.addAlgorithm("Cipher." + CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_KeyWrap, PREFIX + "$CryptoProWrap");
            provider.addAlgorithm("Cipher." + CryptoProObjectIdentifiers.id_Gost28147_89_None_KeyWrap, PREFIX + "$GostWrap");

            provider.addAlgorithm("Mac.GOST3412MAC", PREFIX + "$Mac");
            provider.addAlgorithm("Alg.Alias.Mac.GOST3412_2015", "GOST3412MAC");
        }
    }


}
