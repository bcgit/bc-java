package org.bouncycastle.jcajce.provider.symmetric;

import java.io.IOException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.jcajce.PBKDF2Key;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameters;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseSecretKeyFactory;
import org.bouncycastle.jcajce.provider.symmetric.util.PBE;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;
import org.bouncycastle.jcajce.spec.PBKDF2KeySpec;
import org.bouncycastle.util.Integers;

public class PBEPBKDF2
{
    private static final Map prfCodes = new HashMap();

    static
    {
        prfCodes.put(CryptoProObjectIdentifiers.gostR3411Hmac, Integers.valueOf(PBE.GOST3411));
        prfCodes.put(PKCSObjectIdentifiers.id_hmacWithSHA1, Integers.valueOf(PBE.SHA1));
        prfCodes.put(PKCSObjectIdentifiers.id_hmacWithSHA256, Integers.valueOf(PBE.SHA256));
        prfCodes.put(PKCSObjectIdentifiers.id_hmacWithSHA224, Integers.valueOf(PBE.SHA224));
        prfCodes.put(PKCSObjectIdentifiers.id_hmacWithSHA384, Integers.valueOf(PBE.SHA384));
        prfCodes.put(PKCSObjectIdentifiers.id_hmacWithSHA512, Integers.valueOf(PBE.SHA512));
        prfCodes.put(NISTObjectIdentifiers.id_hmacWithSHA3_256, Integers.valueOf(PBE.SHA3_256));
        prfCodes.put(NISTObjectIdentifiers.id_hmacWithSHA3_224, Integers.valueOf(PBE.SHA3_224));
        prfCodes.put(NISTObjectIdentifiers.id_hmacWithSHA3_384, Integers.valueOf(PBE.SHA3_384));
        prfCodes.put(NISTObjectIdentifiers.id_hmacWithSHA3_512, Integers.valueOf(PBE.SHA3_512));
        prfCodes.put(GMObjectIdentifiers.hmac_sm3, Integers.valueOf(PBE.SM3));
    }

    private PBEPBKDF2()
    {

    }

    public static class AlgParams
        extends BaseAlgorithmParameters
    {
        PBKDF2Params params;

        protected byte[] engineGetEncoded()
        {
            try
            {
                return params.getEncoded(ASN1Encoding.DER);
            }
            catch (IOException e)
            {
                throw new RuntimeException("Oooops! " + e.toString());
            }
        }

        protected byte[] engineGetEncoded(
            String format)
        {
            if (this.isASN1FormatString(format))
            {
                return engineGetEncoded();
            }

            return null;
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(
            Class paramSpec)
            throws InvalidParameterSpecException
        {
            if (paramSpec == PBEParameterSpec.class || paramSpec == AlgorithmParameterSpec.class)
            {
                return new PBEParameterSpec(params.getSalt(),
                    params.getIterationCount().intValue());
            }

            throw new InvalidParameterSpecException("unknown parameter spec passed to PBKDF2 PBE parameters object.");
        }

        protected void engineInit(
            AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException
        {
            if (!(paramSpec instanceof PBEParameterSpec))
            {
                throw new InvalidParameterSpecException("PBEParameterSpec required to initialise a PBKDF2 PBE parameters algorithm parameters object");
            }

            PBEParameterSpec pbeSpec = (PBEParameterSpec)paramSpec;

            this.params = new PBKDF2Params(pbeSpec.getSalt(),
                pbeSpec.getIterationCount());
        }

        protected void engineInit(
            byte[] params)
            throws IOException
        {
            this.params = PBKDF2Params.getInstance(ASN1Primitive.fromByteArray(params));
        }

        protected void engineInit(
            byte[] params,
            String format)
            throws IOException
        {
            if (this.isASN1FormatString(format))
            {
                engineInit(params);
                return;
            }

            throw new IOException("Unknown parameters format in PBKDF2 parameters object");
        }

        protected String engineToString()
        {
            return "PBKDF2 Parameters";
        }
    }

    public static class BasePBKDF2
        extends BaseSecretKeyFactory
    {
        private int scheme;
        private int defaultDigest;

        public BasePBKDF2(String name, int scheme)
        {
            this(name, scheme, SHA1);
        }

        public BasePBKDF2(String name, int scheme, int defaultDigest)
        {
            super(name, PKCSObjectIdentifiers.id_PBKDF2);

            this.scheme = scheme;
            this.defaultDigest = defaultDigest;
        }

        protected SecretKey engineGenerateSecret(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            if (keySpec instanceof PBEKeySpec)
            {
                PBEKeySpec pbeSpec = (PBEKeySpec)keySpec;

                if (pbeSpec.getSalt() == null)
                {
                    return new PBKDF2Key(((PBEKeySpec)keySpec).getPassword(),
                        scheme == PKCS5S2 ? PasswordConverter.ASCII : PasswordConverter.UTF8);
                }

                if (pbeSpec.getIterationCount() <= 0)
                {
                    throw new InvalidKeySpecException("positive iteration count required: "
                        + pbeSpec.getIterationCount());
                }

                if (pbeSpec.getKeyLength() <= 0)
                {
                    throw new InvalidKeySpecException("positive key length required: "
                        + pbeSpec.getKeyLength());
                }

                if (pbeSpec.getPassword().length == 0)
                {
                    throw new IllegalArgumentException("password empty");
                }

                if (pbeSpec instanceof PBKDF2KeySpec)
                {
                    PBKDF2KeySpec spec = (PBKDF2KeySpec)pbeSpec;

                    int digest = getDigestCode(spec.getPrf().getAlgorithm());
                    int keySize = pbeSpec.getKeyLength();
                    int ivSize = -1;    // JDK 1,2 and earlier does not understand simplified version.
                    CipherParameters param = PBE.Util.makePBEMacParameters(pbeSpec, scheme, digest, keySize);

                    return new BCPBEKey(this.algName, this.algOid, scheme, digest, keySize, ivSize, pbeSpec, param);
                }
                else
                {
                    int digest = defaultDigest;
                    int keySize = pbeSpec.getKeyLength();
                    int ivSize = -1;    // JDK 1,2 and earlier does not understand simplified version.
                    CipherParameters param = PBE.Util.makePBEMacParameters(pbeSpec, scheme, digest, keySize);

                    return new BCPBEKey(this.algName, this.algOid, scheme, digest, keySize, ivSize, pbeSpec, param);
                }
            }

            throw new InvalidKeySpecException("Invalid KeySpec");
        }


        private int getDigestCode(ASN1ObjectIdentifier algorithm)
            throws InvalidKeySpecException
        {
            Integer code = (Integer)prfCodes.get(algorithm);
            if (code != null)
            {
                return code.intValue();
            }
            
            throw new InvalidKeySpecException("Invalid KeySpec: unknown PRF algorithm " + algorithm);
        }
    }

    public static class PBKDF2withUTF8
        extends BasePBKDF2
    {
        public PBKDF2withUTF8()
        {
            super("PBKDF2", PKCS5S2_UTF8);
        }
    }

    public static class PBKDF2withSHA224
        extends BasePBKDF2
    {
        public PBKDF2withSHA224()
        {
            super("PBKDF2", PKCS5S2_UTF8, SHA224);
        }
    }

    public static class PBKDF2withSHA256
        extends BasePBKDF2
    {
        public PBKDF2withSHA256()
        {
            super("PBKDF2", PKCS5S2_UTF8, SHA256);
        }
    }

    public static class PBKDF2withSHA384
        extends BasePBKDF2
    {
        public PBKDF2withSHA384()
        {
            super("PBKDF2", PKCS5S2_UTF8, SHA384);
        }
    }

    public static class PBKDF2withSHA512
        extends BasePBKDF2
    {
        public PBKDF2withSHA512()
        {
            super("PBKDF2", PKCS5S2_UTF8, SHA512);
        }
    }

    public static class PBKDF2withGOST3411
        extends BasePBKDF2
    {
        public PBKDF2withGOST3411()
        {
            super("PBKDF2", PKCS5S2_UTF8, GOST3411);
        }
    }

    public static class PBKDF2withSHA3_224
        extends BasePBKDF2
    {
        public PBKDF2withSHA3_224()
        {
            super("PBKDF2", PKCS5S2_UTF8, SHA3_224);
        }
    }

    public static class PBKDF2withSHA3_256
        extends BasePBKDF2
    {
        public PBKDF2withSHA3_256()
        {
            super("PBKDF2", PKCS5S2_UTF8, SHA3_256);
        }
    }

    public static class PBKDF2withSHA3_384
        extends BasePBKDF2
    {
        public PBKDF2withSHA3_384()
        {
            super("PBKDF2", PKCS5S2_UTF8, SHA3_384);
        }
    }

    public static class PBKDF2withSHA3_512
        extends BasePBKDF2
    {
        public PBKDF2withSHA3_512()
        {
            super("PBKDF2", PKCS5S2_UTF8, SHA3_512);
        }
    }

    public static class PBKDF2with8BIT
        extends BasePBKDF2
    {
        public PBKDF2with8BIT()
        {
            super("PBKDF2", PKCS5S2);
        }
    }

    public static class PBKDF2withSM3
        extends BasePBKDF2
    {
        public PBKDF2withSM3() {
            super("PBKDF2", PKCS5S2_UTF8, SM3);
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = PBEPBKDF2.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("AlgorithmParameters.PBKDF2", PREFIX + "$AlgParams");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + PKCSObjectIdentifiers.id_PBKDF2, "PBKDF2");
            provider.addAlgorithm("SecretKeyFactory.PBKDF2", PREFIX + "$PBKDF2withUTF8");
            provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBKDF2WITHHMACSHA1", "PBKDF2");
            provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBKDF2WITHHMACSHA1ANDUTF8", "PBKDF2");
            provider.addAlgorithm("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers.id_PBKDF2, "PBKDF2");
            provider.addAlgorithm("SecretKeyFactory.PBKDF2WITHASCII", PREFIX + "$PBKDF2with8BIT");
            provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBKDF2WITH8BIT", "PBKDF2WITHASCII");
            provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBKDF2WITHHMACSHA1AND8BIT", "PBKDF2WITHASCII");
            provider.addAlgorithm("SecretKeyFactory.PBKDF2WITHHMACSHA224", PREFIX + "$PBKDF2withSHA224");
            provider.addAlgorithm("SecretKeyFactory.PBKDF2WITHHMACSHA256", PREFIX + "$PBKDF2withSHA256");
            provider.addAlgorithm("SecretKeyFactory.PBKDF2WITHHMACSHA384", PREFIX + "$PBKDF2withSHA384");
            provider.addAlgorithm("SecretKeyFactory.PBKDF2WITHHMACSHA512", PREFIX + "$PBKDF2withSHA512");
            provider.addAlgorithm("SecretKeyFactory.PBKDF2WITHHMACSHA3-224", PREFIX + "$PBKDF2withSHA3_224");
            provider.addAlgorithm("SecretKeyFactory.PBKDF2WITHHMACSHA3-256", PREFIX + "$PBKDF2withSHA3_256");
            provider.addAlgorithm("SecretKeyFactory.PBKDF2WITHHMACSHA3-384", PREFIX + "$PBKDF2withSHA3_384");
            provider.addAlgorithm("SecretKeyFactory.PBKDF2WITHHMACSHA3-512", PREFIX + "$PBKDF2withSHA3_512");
            provider.addAlgorithm("SecretKeyFactory.PBKDF2WITHHMACGOST3411", PREFIX + "$PBKDF2withGOST3411");
            provider.addAlgorithm("SecretKeyFactory.PBKDF2WITHHMACSM3", PREFIX + "$PBKDF2withSM3");
        }
    }
}
