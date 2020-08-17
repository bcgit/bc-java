package org.bouncycastle.jcajce.provider.symmetric.util;

import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.digests.MD2Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.digests.TigerDigest;
import org.bouncycastle.crypto.generators.OpenSSLPBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S1ParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.DESParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.util.DigestFactory;

public interface PBE
{
    //
    // PBE Based encryption constants - by default we do PKCS12 with SHA-1
    //
    static final int        MD5          = 0;
    static final int        SHA1         = 1;
    static final int        RIPEMD160    = 2;
    static final int        TIGER        = 3;
    static final int        SHA256       = 4;
    static final int        MD2          = 5;
    static final int        GOST3411     = 6;
    static final int        SHA224       = 7;
    static final int        SHA384       = 8;
    static final int        SHA512       = 9;
    static final int        SHA3_224     = 10;
    static final int        SHA3_256     = 11;
    static final int        SHA3_384     = 12;
    static final int        SHA3_512     = 13;
    static final int        SM3          = 14;

    static final int        PKCS5S1      = 0;
    static final int        PKCS5S2      = 1;
    static final int        PKCS12       = 2;
    static final int        OPENSSL      = 3;
    static final int        PKCS5S1_UTF8 = 4;
    static final int        PKCS5S2_UTF8 = 5;

    /**
     * uses the appropriate mixer to generate the key and IV if necessary.
     */
    static class Util
    {
        static private PBEParametersGenerator makePBEGenerator(
            int                     type,
            int                     hash)
        {
            PBEParametersGenerator  generator;
    
            if (type == PKCS5S1 || type == PKCS5S1_UTF8)
            {
                switch (hash)
                {
                case MD2:
                    generator = new PKCS5S1ParametersGenerator(new MD2Digest());
                    break;
                case MD5:
                    generator = new PKCS5S1ParametersGenerator(DigestFactory.createMD5());
                    break;
                case SHA1:
                    generator = new PKCS5S1ParametersGenerator(DigestFactory.createSHA1());
                    break;
                default:
                    throw new IllegalStateException("PKCS5 scheme 1 only supports MD2, MD5 and SHA1.");
                }
            }
            else if (type == PKCS5S2 || type == PKCS5S2_UTF8)
            {
                switch (hash)
                {
                case MD2:
                    generator = new PKCS5S2ParametersGenerator(new MD2Digest());
                    break;
                case MD5:
                    generator = new PKCS5S2ParametersGenerator(DigestFactory.createMD5());
                    break;
                case SHA1:
                    generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA1());
                    break;
                case RIPEMD160:
                    generator = new PKCS5S2ParametersGenerator(new RIPEMD160Digest());
                    break;
                case TIGER:
                    generator = new PKCS5S2ParametersGenerator(new TigerDigest());
                    break;
                case SHA256:
                    generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA256());
                    break;
                case GOST3411:
                    generator = new PKCS5S2ParametersGenerator(new GOST3411Digest());
                    break;
                case SHA224:
                    generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA224());
                    break;
                case SHA384:
                    generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA384());
                    break;
                case SHA512:
                    generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA512());
                    break;
                case SHA3_224:
                    generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA3_224());
                    break;
                case SHA3_256:
                     generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA3_256());
                     break;
                case SHA3_384:
                    generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA3_384());
                    break;
                case SHA3_512:
                    generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA3_512());
                    break;
                case SM3:
                    generator = new PKCS5S2ParametersGenerator(new SM3Digest());
                    break;
                default:
                    throw new IllegalStateException("unknown digest scheme for PBE PKCS5S2 encryption.");
                }
            }
            else if (type == PKCS12)
            {
                switch (hash)
                {
                case MD2:
                    generator = new PKCS12ParametersGenerator(new MD2Digest());
                    break;
                case MD5:
                    generator = new PKCS12ParametersGenerator(DigestFactory.createMD5());
                    break;
                case SHA1:
                    generator = new PKCS12ParametersGenerator(DigestFactory.createSHA1());
                    break;
                case RIPEMD160:
                    generator = new PKCS12ParametersGenerator(new RIPEMD160Digest());
                    break;
                case TIGER:
                    generator = new PKCS12ParametersGenerator(new TigerDigest());
                    break;
                case SHA256:
                    generator = new PKCS12ParametersGenerator(DigestFactory.createSHA256());
                    break;
                case GOST3411:
                    generator = new PKCS12ParametersGenerator(new GOST3411Digest());
                    break;
                case SHA224:
                    generator = new PKCS12ParametersGenerator(DigestFactory.createSHA224());
                    break;
                case SHA384:
                    generator = new PKCS12ParametersGenerator(DigestFactory.createSHA384());
                    break;
                case SHA512:
                    generator = new PKCS12ParametersGenerator(DigestFactory.createSHA512());
                    break;
                default:
                    throw new IllegalStateException("unknown digest scheme for PBE encryption.");
                }
            }
            else
            {
                generator = new OpenSSLPBEParametersGenerator();
            }
    
            return generator;
        }

        /**
         * construct a key and iv (if necessary) suitable for use with a
         * Cipher.
         */
        public static CipherParameters makePBEParameters(
            byte[] pbeKey,
            int scheme,
            int digest,
            int keySize,
            int ivSize,
            AlgorithmParameterSpec spec,
            String targetAlgorithm)
            throws InvalidAlgorithmParameterException
        {
            if ((spec == null) || !(spec instanceof PBEParameterSpec))
            {
                throw new InvalidAlgorithmParameterException("Need a PBEParameter spec with a PBE key.");
            }

            PBEParameterSpec        pbeParam = (PBEParameterSpec)spec;
            PBEParametersGenerator  generator = makePBEGenerator(scheme, digest);
            byte[]                  key = pbeKey;
            CipherParameters        param;

//            if (pbeKey.shouldTryWrongPKCS12())
//            {
//                key = new byte[2];
//            }

            generator.init(key, pbeParam.getSalt(), pbeParam.getIterationCount());

            if (ivSize != 0)
            {
                param = generator.generateDerivedParameters(keySize, ivSize);
            }
            else
            {
                param = generator.generateDerivedParameters(keySize);
            }

            if (targetAlgorithm.startsWith("DES"))
            {
                if (param instanceof ParametersWithIV)
                {
                    KeyParameter    kParam = (KeyParameter)((ParametersWithIV)param).getParameters();

                    DESParameters.setOddParity(kParam.getKey());
                }
                else
                {
                    KeyParameter    kParam = (KeyParameter)param;

                    DESParameters.setOddParity(kParam.getKey());
                }
            }

            return param;
        }

        /**
         * construct a key and iv (if necessary) suitable for use with a 
         * Cipher.
         */
        public static CipherParameters makePBEParameters(
            BCPBEKey pbeKey,
            AlgorithmParameterSpec spec,
            String targetAlgorithm)
        {
            if ((spec == null) || !(spec instanceof PBEParameterSpec))
            {
                throw new IllegalArgumentException("Need a PBEParameter spec with a PBE key.");
            }
    
            PBEParameterSpec        pbeParam = (PBEParameterSpec)spec;
            PBEParametersGenerator  generator = makePBEGenerator(pbeKey.getType(), pbeKey.getDigest());
            byte[]                  key = pbeKey.getEncoded();
            CipherParameters        param;
    
            if (pbeKey.shouldTryWrongPKCS12())
            {
                key = new byte[2];
            }
            
            generator.init(key, pbeParam.getSalt(), pbeParam.getIterationCount());

            if (pbeKey.getIvSize() != 0)
            {
                param = generator.generateDerivedParameters(pbeKey.getKeySize(), pbeKey.getIvSize());
            }
            else
            {
                param = generator.generateDerivedParameters(pbeKey.getKeySize());
            }

            if (targetAlgorithm.startsWith("DES"))
            {
                if (param instanceof ParametersWithIV)
                {
                    KeyParameter    kParam = (KeyParameter)((ParametersWithIV)param).getParameters();

                    DESParameters.setOddParity(kParam.getKey());
                }
                else
                {
                    KeyParameter    kParam = (KeyParameter)param;

                    DESParameters.setOddParity(kParam.getKey());
                }
            }

            return param;
        }

        /**
         * generate a PBE based key suitable for a MAC algorithm, the
         * key size is chosen according the MAC size, or the hashing algorithm,
         * whichever is greater.
         */
        public static CipherParameters makePBEMacParameters(
            BCPBEKey pbeKey,
            AlgorithmParameterSpec spec)
        {
            if ((spec == null) || !(spec instanceof PBEParameterSpec))
            {
                throw new IllegalArgumentException("Need a PBEParameter spec with a PBE key.");
            }
    
            PBEParameterSpec        pbeParam = (PBEParameterSpec)spec;
            PBEParametersGenerator  generator = makePBEGenerator(pbeKey.getType(), pbeKey.getDigest());
            byte[]                  key = pbeKey.getEncoded();
            CipherParameters        param;
            
            generator.init(key, pbeParam.getSalt(), pbeParam.getIterationCount());

            param = generator.generateDerivedMacParameters(pbeKey.getKeySize());

            return param;
        }

        /**
         * generate a PBE based key suitable for a MAC algorithm, the
         * key size is chosen according the MAC size, or the hashing algorithm,
         * whichever is greater.
         */
        public static CipherParameters makePBEMacParameters(
            PBEKeySpec keySpec,
            int type,
            int hash,
            int keySize)
        {
            PBEParametersGenerator  generator = makePBEGenerator(type, hash);
            byte[]                  key;
            CipherParameters        param;

            key = convertPassword(type, keySpec);

            generator.init(key, keySpec.getSalt(), keySpec.getIterationCount());

            param = generator.generateDerivedMacParameters(keySize);

            for (int i = 0; i != key.length; i++)
            {
                key[i] = 0;
            }

            return param;
        }

        /**
         * construct a key and iv (if necessary) suitable for use with a 
         * Cipher.
         */
        public static CipherParameters makePBEParameters(
            PBEKeySpec keySpec,
            int type,
            int hash,
            int keySize,
            int ivSize)
        {    
            PBEParametersGenerator  generator = makePBEGenerator(type, hash);
            byte[]                  key;
            CipherParameters        param;

            key = convertPassword(type, keySpec);

            generator.init(key, keySpec.getSalt(), keySpec.getIterationCount());
    
            if (ivSize != 0)
            {
                param = generator.generateDerivedParameters(keySize, ivSize);
            }
            else
            {
                param = generator.generateDerivedParameters(keySize);
            }
    
            for (int i = 0; i != key.length; i++)
            {
                key[i] = 0;
            }
    
            return param;
        }

        /**
         * generate a PBE based key suitable for a MAC algorithm, the
         * key size is chosen according the MAC size, or the hashing algorithm,
         * whichever is greater.
         */
        public static CipherParameters makePBEMacParameters(
            SecretKey key,
            int type,
            int hash,
            int keySize,
            PBEParameterSpec pbeSpec)
        {
            PBEParametersGenerator  generator = makePBEGenerator(type, hash);
            CipherParameters        param;
    
            byte[] keyBytes = key.getEncoded();
            
            generator.init(key.getEncoded(), pbeSpec.getSalt(), pbeSpec.getIterationCount());

            param = generator.generateDerivedMacParameters(keySize);

            for (int i = 0; i != keyBytes.length; i++)
            {
                keyBytes[i] = 0;
            }
    
            return param;
        }

        private static byte[] convertPassword(int type, PBEKeySpec keySpec)
        {
            byte[] key;

            if (type == PKCS12)
            {
                key = PBEParametersGenerator.PKCS12PasswordToBytes(keySpec.getPassword());
            }
            else if (type == PKCS5S2_UTF8 || type == PKCS5S1_UTF8)
            {
                key = PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(keySpec.getPassword());
            }
            else
            {
                key = PBEParametersGenerator.PKCS5PasswordToBytes(keySpec.getPassword());
            }
            return key;
        }
    }
}
