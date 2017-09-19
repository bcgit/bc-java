package org.bouncycastle.jcajce.provider.symmetric;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

import java.util.HashMap;
import java.util.Map;


public class GOST3412_2015 {

    private static Map<ASN1ObjectIdentifier, String> oidMappings = new HashMap<ASN1ObjectIdentifier, String>();
    private static Map<String, ASN1ObjectIdentifier> nameMappings = new HashMap<String, ASN1ObjectIdentifier>();


    static {
//init maps here
    }


    public static class Mappings
        extends AlgorithmProvider {
        private static final String PREFIX = GOST3412_2015.class.getName();

        public Mappings() {
        }

        public void configure(ConfigurableProvider provider) {
            provider.addAlgorithm("Cipher.GOST3412_2015", PREFIX + "$ECB");
            provider.addAlgorithm("Alg.Alias.Cipher.GOST", "GOST3412_2015");
            provider.addAlgorithm("Alg.Alias.Cipher.GOST-3412", "GOST3412_2015");
            provider.addAlgorithm("Cipher." + CryptoProObjectIdentifiers.gostR28147_gcfb, PREFIX + "$GCFB");

            provider.addAlgorithm("KeyGenerator.GOST3412_2015", PREFIX + "$KeyGen");
            provider.addAlgorithm("Alg.Alias.KeyGenerator.GOST", "GOST3412_2015");
            provider.addAlgorithm("Alg.Alias.KeyGenerator.GOST-3412", "GOST3412_2015");
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
