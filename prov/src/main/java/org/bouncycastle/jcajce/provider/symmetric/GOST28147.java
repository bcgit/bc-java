package org.bouncycastle.jcajce.provider.symmetric;

import java.io.IOException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.GOST28147Parameters;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.engines.CryptoProWrapEngine;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.engines.GOST28147WrapEngine;
import org.bouncycastle.crypto.macs.GOST28147Mac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.GCFBBlockCipher;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameters;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseWrapCipher;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;
import org.bouncycastle.jcajce.spec.GOST28147ParameterSpec;
import org.bouncycastle.jcajce.spec.GOST28147WrapParameterSpec;

public final class GOST28147
{
    private static Map<ASN1ObjectIdentifier, String> oidMappings = new HashMap<ASN1ObjectIdentifier, String>();
    private static Map<String, ASN1ObjectIdentifier> nameMappings = new HashMap<String, ASN1ObjectIdentifier>();

    static
    {
        oidMappings.put(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_TestParamSet, "E-TEST");
        oidMappings.put(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_A_ParamSet, "E-A");
        oidMappings.put(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_B_ParamSet, "E-B");
        oidMappings.put(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_C_ParamSet, "E-C");
        oidMappings.put(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_D_ParamSet, "E-D");

        nameMappings.put("E-A", CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_A_ParamSet);
        nameMappings.put("E-B", CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_B_ParamSet);
        nameMappings.put("E-C", CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_C_ParamSet);
        nameMappings.put("E-D", CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_D_ParamSet);
    }

    private GOST28147()
    {
    }

    public static class ECB
        extends BaseBlockCipher
    {
        public ECB()
        {
            super(new GOST28147Engine());
        }
    }

    public static class CBC
        extends BaseBlockCipher
    {
        public CBC()
        {
            super(new CBCBlockCipher(new GOST28147Engine()), 64);
        }
    }

    public static class GCFB
        extends BaseBlockCipher
    {
        public GCFB()
        {
            super(new BufferedBlockCipher(new GCFBBlockCipher(new GOST28147Engine())), 64);
        }
    }

    public static class GostWrap
        extends BaseWrapCipher
    {
        public GostWrap()
        {
            super(new GOST28147WrapEngine());
        }
    }

    public static class CryptoProWrap
        extends BaseWrapCipher
    {
        public CryptoProWrap()
        {
            super(new CryptoProWrapEngine());
        }
    }

    /**
     * GOST28147
     */
    public static class Mac
        extends BaseMac
    {
        public Mac()
        {
            super(new GOST28147Mac());
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
            super("GOST28147", keySize, new CipherKeyGenerator());
        }
    }

    public abstract static class BaseAlgParams
        extends BaseAlgorithmParameters
    {
        private ASN1ObjectIdentifier sBox = CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_A_ParamSet;
        private byte[] iv;

        protected final void engineInit(byte[] encoding)
            throws IOException
        {
            engineInit(encoding, "ASN.1");
        }

        protected final byte[] engineGetEncoded()
            throws IOException
        {
            return engineGetEncoded("ASN.1");
        }

        protected final byte[] engineGetEncoded(
            String format)
            throws IOException
        {
            if (isASN1FormatString(format))
            {
                return localGetEncoded();
            }

            throw new IOException("Unknown parameter format: " + format);
        }

        protected final void engineInit(
            byte[] params,
            String format)
            throws IOException
        {
            if (params == null)
            {
                throw new NullPointerException("Encoded parameters cannot be null");
            }

            if (isASN1FormatString(format))
            {
                try
                {
                    localInit(params);
                }
                catch (IOException e)
                {
                    throw e;
                }
                catch (Exception e)
                {
                    throw new IOException("Parameter parsing failed: " + e.getMessage());
                }
            }
            else
            {
                throw new IOException("Unknown parameter format: " + format);
            }
        }

        protected byte[] localGetEncoded()
            throws IOException
        {
            return new GOST28147Parameters(iv, sBox).getEncoded();
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(
            Class paramSpec)
            throws InvalidParameterSpecException
        {
            if (paramSpec == IvParameterSpec.class)
            {
                return new IvParameterSpec(iv);
            }

            if (paramSpec == GOST28147ParameterSpec.class || paramSpec == AlgorithmParameterSpec.class)
            {
                return new GOST28147ParameterSpec(sBox, iv);
            }

            throw new InvalidParameterSpecException("AlgorithmParameterSpec not recognized: " + paramSpec.getName());
        }

        protected void engineInit(
            AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException
        {
            if (paramSpec instanceof IvParameterSpec)
            {
                this.iv = ((IvParameterSpec)paramSpec).getIV();
            }
            else if (paramSpec instanceof GOST28147ParameterSpec)
            {
                this.iv = ((GOST28147ParameterSpec)paramSpec).getIV();
                try
                {
                    this.sBox = getSBoxOID((((GOST28147ParameterSpec)paramSpec).getSBox()));
                }
                catch (IllegalArgumentException e)
                {
                    throw new InvalidParameterSpecException(e.getMessage());
                }
            }
            else
            {
                throw new InvalidParameterSpecException("IvParameterSpec required to initialise a IV parameters algorithm parameters object");
            }
        }

        protected static ASN1ObjectIdentifier getSBoxOID(String name)
        {
            ASN1ObjectIdentifier oid = nameMappings.get(name);

            if (oid == null)
            {
                throw new IllegalArgumentException("Unknown SBOX name: " + name);
            }

            return oid;
        }

        protected static ASN1ObjectIdentifier getSBoxOID(byte[] sBox)
        {
            return getSBoxOID(GOST28147Engine.getSBoxName(sBox));
        }

        abstract void localInit(byte[] params) throws IOException;
    }

    public static class AlgParams
        extends BaseAlgParams
    {
        private ASN1ObjectIdentifier sBox = CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_A_ParamSet;
        private byte[] iv;

        protected byte[] localGetEncoded()
            throws IOException
        {
            return new GOST28147Parameters(iv, sBox).getEncoded();
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(
            Class paramSpec)
            throws InvalidParameterSpecException
        {
            if (paramSpec == IvParameterSpec.class)
            {
                return new IvParameterSpec(iv);
            }

            if (paramSpec == GOST28147ParameterSpec.class || paramSpec == AlgorithmParameterSpec.class)
            {
                return new GOST28147ParameterSpec(sBox, iv);
            }

            throw new InvalidParameterSpecException("AlgorithmParameterSpec not recognized: " + paramSpec.getName());
        }

        protected void engineInit(
            AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException
        {
            if (paramSpec instanceof IvParameterSpec)
            {
                this.iv = ((IvParameterSpec)paramSpec).getIV();
            }
            else if (paramSpec instanceof GOST28147ParameterSpec)
            {
                this.iv = ((GOST28147ParameterSpec)paramSpec).getIV();
                try
                {
                    this.sBox = getSBoxOID((((GOST28147ParameterSpec)paramSpec).getSBox()));
                }
                catch (IllegalArgumentException e)
                {
                    throw new InvalidParameterSpecException(e.getMessage());
                }
            }
            else
            {
                throw new InvalidParameterSpecException("IvParameterSpec required to initialise a IV parameters algorithm parameters object");
            }
        }

        protected void localInit(
            byte[] params)
            throws IOException
        {
            ASN1Primitive asn1Params = ASN1Primitive.fromByteArray(params);

            if (asn1Params instanceof ASN1OctetString)
            {
                this.iv = ASN1OctetString.getInstance(asn1Params).getOctets();
            }
            else if (asn1Params instanceof ASN1Sequence)
            {
                GOST28147Parameters gParams = GOST28147Parameters.getInstance(asn1Params);

                this.sBox = gParams.getEncryptionParamSet();
                this.iv = gParams.getIV();
            }
            else
            {
                throw new IOException("Unable to recognize parameters");
            }
        }

        protected String engineToString()
        {
            return "GOST 28147 IV Parameters";
        }
    }

    public static class WrapAlgParams
        extends BaseAlgParams
    {
        private ASN1ObjectIdentifier sBox = CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_A_ParamSet;
        private byte[] ukm;

        protected byte[] localGetEncoded()
            throws IOException
        {
            return new GOST28147Parameters(ukm, sBox).getEncoded();
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(
            Class paramSpec)
            throws InvalidParameterSpecException
        {
            if (paramSpec == GOST28147WrapParameterSpec.class || paramSpec == AlgorithmParameterSpec.class)
            {
                return new GOST28147WrapParameterSpec(sBox, ukm);
            }

            throw new InvalidParameterSpecException("AlgorithmParameterSpec not recognized: " + paramSpec.getName());
        }

        protected void engineInit(
            AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException
        {
            if (paramSpec instanceof GOST28147WrapParameterSpec)
            {
                this.ukm = ((GOST28147WrapParameterSpec)paramSpec).getUKM();
                try
                {
                    this.sBox = getSBoxOID((((GOST28147WrapParameterSpec)paramSpec).getSBox()));
                }
                catch (IllegalArgumentException e)
                {
                    throw new InvalidParameterSpecException(e.getMessage());
                }
            }
            else
            {
                throw new InvalidParameterSpecException("GOST28147WrapParameterSpec required to initialise a Wrap parameters algorithm parameters object");
            }
        }

        protected void localInit(
            byte[] params)
            throws IOException
        {
            ASN1Primitive asn1Params = ASN1Primitive.fromByteArray(params);

            // can be either Gost2814789KeyWrapParameters or GostR3410TransportParameters
            if (asn1Params instanceof ASN1Sequence)
            {
                ASN1Sequence gParams = ASN1Sequence.getInstance(asn1Params);

                this.sBox = ASN1ObjectIdentifier.getInstance(gParams.getObjectAt(0));
                if (gParams.size() > 1)
                {
                    if (gParams.size() == 2)
                    {
                        this.ukm = ASN1OctetString.getInstance(gParams.getObjectAt(1)).getOctets();
                    }
                    else if (gParams.size() == 3)
                    {
                        this.ukm = ASN1OctetString.getInstance(gParams.getObjectAt(2)).getOctets();
                    }
                }
            }
            else
            {
                throw new IOException("Unable to recognize parameters");
            }
        }

        protected String engineToString()
        {
            return "GOST 28147 Wrap Parameters";
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = GOST28147.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("Cipher.GOST28147", PREFIX + "$ECB");
            provider.addAlgorithm("Alg.Alias.Cipher.GOST", "GOST28147");
            provider.addAlgorithm("Alg.Alias.Cipher.GOST-28147", "GOST28147");
            provider.addAlgorithm("Cipher." + CryptoProObjectIdentifiers.gostR28147_gcfb, PREFIX + "$GCFB");

            provider.addAlgorithm("KeyGenerator.GOST28147", PREFIX + "$KeyGen");
            provider.addAlgorithm("Alg.Alias.KeyGenerator.GOST", "GOST28147");
            provider.addAlgorithm("Alg.Alias.KeyGenerator.GOST-28147", "GOST28147");
            provider.addAlgorithm("Alg.Alias.KeyGenerator." + CryptoProObjectIdentifiers.gostR28147_gcfb, "GOST28147");

            provider.addAlgorithm("AlgorithmParameters." + CryptoProObjectIdentifiers.gostR28147_gcfb, PREFIX + "$AlgParams");

            provider.addAlgorithm("Cipher." + CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_KeyWrap, PREFIX + "$CryptoProWrap");
            provider.addAlgorithm("Cipher." + CryptoProObjectIdentifiers.id_Gost28147_89_None_KeyWrap, PREFIX + "$GostWrap");

            provider.addAlgorithm("AlgorithmParameters." + CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_KeyWrap, PREFIX + "$WrapAlgParams");
            provider.addAlgorithm("AlgorithmParameters." + CryptoProObjectIdentifiers.id_Gost28147_89_None_KeyWrap, PREFIX + "$WrapAlgParams");

            provider.addAlgorithm("Mac.GOST28147MAC", PREFIX + "$Mac");
            provider.addAlgorithm("Alg.Alias.Mac.GOST28147", "GOST28147MAC");
        }
    }
}
