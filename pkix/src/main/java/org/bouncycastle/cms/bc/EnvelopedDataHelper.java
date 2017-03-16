package org.bouncycastle.cms.bc;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.misc.CAST5CBCParameters;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RC2CBCParameter;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.CAST5Engine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.engines.RFC3211WrapEngine;
import org.bouncycastle.crypto.generators.DESKeyGenerator;
import org.bouncycastle.crypto.generators.DESedeKeyGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.RC2Parameters;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestProvider;

class EnvelopedDataHelper
{
    protected static final Map BASE_CIPHER_NAMES = new HashMap();
    protected static final Map MAC_ALG_NAMES = new HashMap();

    private static final Map prfs = createTable();

    private static Map createTable()
    {
        Map table = new HashMap();

        table.put(PKCSObjectIdentifiers.id_hmacWithSHA1, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new SHA1Digest();
            }
        });
        table.put(PKCSObjectIdentifiers.id_hmacWithSHA224, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new SHA224Digest();
            }
        });
        table.put(PKCSObjectIdentifiers.id_hmacWithSHA256, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new SHA256Digest();
            }
        });
        table.put(PKCSObjectIdentifiers.id_hmacWithSHA384, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new SHA384Digest();
            }
        });
        table.put(PKCSObjectIdentifiers.id_hmacWithSHA512, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new SHA512Digest();
            }
        });

        return Collections.unmodifiableMap(table);
    }

    static
    {
        BASE_CIPHER_NAMES.put(CMSAlgorithm.DES_EDE3_CBC, "DESEDE");
        BASE_CIPHER_NAMES.put(CMSAlgorithm.AES128_CBC, "AES");
        BASE_CIPHER_NAMES.put(CMSAlgorithm.AES192_CBC, "AES");
        BASE_CIPHER_NAMES.put(CMSAlgorithm.AES256_CBC, "AES");

        MAC_ALG_NAMES.put(CMSAlgorithm.DES_EDE3_CBC, "DESEDEMac");
        MAC_ALG_NAMES.put(CMSAlgorithm.AES128_CBC, "AESMac");
        MAC_ALG_NAMES.put(CMSAlgorithm.AES192_CBC, "AESMac");
        MAC_ALG_NAMES.put(CMSAlgorithm.AES256_CBC, "AESMac");
        MAC_ALG_NAMES.put(CMSAlgorithm.RC2_CBC, "RC2Mac");
    }

    private static final short[] rc2Table = {
        0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a, 0xb0, 0x93, 0xd1, 0x9c, 0x1b, 0x33, 0xfd, 0xd0,
        0x30, 0x04, 0xb6, 0xdc, 0x7d, 0xdf, 0x32, 0x4b, 0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21, 0x5a,
        0x41, 0x9f, 0xe1, 0xd9, 0x4a, 0x4d, 0x9e, 0xda, 0xa0, 0x68, 0x2c, 0xc3, 0x27, 0x5f, 0x80, 0x36,
        0x3e, 0xee, 0xfb, 0x95, 0x1a, 0xfe, 0xce, 0xa8, 0x34, 0xa9, 0x13, 0xf0, 0xa6, 0x3f, 0xd8, 0x0c,
        0x78, 0x24, 0xaf, 0x23, 0x52, 0xc1, 0x67, 0x17, 0xf5, 0x66, 0x90, 0xe7, 0xe8, 0x07, 0xb8, 0x60,
        0x48, 0xe6, 0x1e, 0x53, 0xf3, 0x92, 0xa4, 0x72, 0x8c, 0x08, 0x15, 0x6e, 0x86, 0x00, 0x84, 0xfa,
        0xf4, 0x7f, 0x8a, 0x42, 0x19, 0xf6, 0xdb, 0xcd, 0x14, 0x8d, 0x50, 0x12, 0xba, 0x3c, 0x06, 0x4e,
        0xec, 0xb3, 0x35, 0x11, 0xa1, 0x88, 0x8e, 0x2b, 0x94, 0x99, 0xb7, 0x71, 0x74, 0xd3, 0xe4, 0xbf,
        0x3a, 0xde, 0x96, 0x0e, 0xbc, 0x0a, 0xed, 0x77, 0xfc, 0x37, 0x6b, 0x03, 0x79, 0x89, 0x62, 0xc6,
        0xd7, 0xc0, 0xd2, 0x7c, 0x6a, 0x8b, 0x22, 0xa3, 0x5b, 0x05, 0x5d, 0x02, 0x75, 0xd5, 0x61, 0xe3,
        0x18, 0x8f, 0x55, 0x51, 0xad, 0x1f, 0x0b, 0x5e, 0x85, 0xe5, 0xc2, 0x57, 0x63, 0xca, 0x3d, 0x6c,
        0xb4, 0xc5, 0xcc, 0x70, 0xb2, 0x91, 0x59, 0x0d, 0x47, 0x20, 0xc8, 0x4f, 0x58, 0xe0, 0x01, 0xe2,
        0x16, 0x38, 0xc4, 0x6f, 0x3b, 0x0f, 0x65, 0x46, 0xbe, 0x7e, 0x2d, 0x7b, 0x82, 0xf9, 0x40, 0xb5,
        0x1d, 0x73, 0xf8, 0xeb, 0x26, 0xc7, 0x87, 0x97, 0x25, 0x54, 0xb1, 0x28, 0xaa, 0x98, 0x9d, 0xa5,
        0x64, 0x6d, 0x7a, 0xd4, 0x10, 0x81, 0x44, 0xef, 0x49, 0xd6, 0xae, 0x2e, 0xdd, 0x76, 0x5c, 0x2f,
        0xa7, 0x1c, 0xc9, 0x09, 0x69, 0x9a, 0x83, 0xcf, 0x29, 0x39, 0xb9, 0xe9, 0x4c, 0xff, 0x43, 0xab
    };

    private static final short[] rc2Ekb = {
        0x5d, 0xbe, 0x9b, 0x8b, 0x11, 0x99, 0x6e, 0x4d, 0x59, 0xf3, 0x85, 0xa6, 0x3f, 0xb7, 0x83, 0xc5,
        0xe4, 0x73, 0x6b, 0x3a, 0x68, 0x5a, 0xc0, 0x47, 0xa0, 0x64, 0x34, 0x0c, 0xf1, 0xd0, 0x52, 0xa5,
        0xb9, 0x1e, 0x96, 0x43, 0x41, 0xd8, 0xd4, 0x2c, 0xdb, 0xf8, 0x07, 0x77, 0x2a, 0xca, 0xeb, 0xef,
        0x10, 0x1c, 0x16, 0x0d, 0x38, 0x72, 0x2f, 0x89, 0xc1, 0xf9, 0x80, 0xc4, 0x6d, 0xae, 0x30, 0x3d,
        0xce, 0x20, 0x63, 0xfe, 0xe6, 0x1a, 0xc7, 0xb8, 0x50, 0xe8, 0x24, 0x17, 0xfc, 0x25, 0x6f, 0xbb,
        0x6a, 0xa3, 0x44, 0x53, 0xd9, 0xa2, 0x01, 0xab, 0xbc, 0xb6, 0x1f, 0x98, 0xee, 0x9a, 0xa7, 0x2d,
        0x4f, 0x9e, 0x8e, 0xac, 0xe0, 0xc6, 0x49, 0x46, 0x29, 0xf4, 0x94, 0x8a, 0xaf, 0xe1, 0x5b, 0xc3,
        0xb3, 0x7b, 0x57, 0xd1, 0x7c, 0x9c, 0xed, 0x87, 0x40, 0x8c, 0xe2, 0xcb, 0x93, 0x14, 0xc9, 0x61,
        0x2e, 0xe5, 0xcc, 0xf6, 0x5e, 0xa8, 0x5c, 0xd6, 0x75, 0x8d, 0x62, 0x95, 0x58, 0x69, 0x76, 0xa1,
        0x4a, 0xb5, 0x55, 0x09, 0x78, 0x33, 0x82, 0xd7, 0xdd, 0x79, 0xf5, 0x1b, 0x0b, 0xde, 0x26, 0x21,
        0x28, 0x74, 0x04, 0x97, 0x56, 0xdf, 0x3c, 0xf0, 0x37, 0x39, 0xdc, 0xff, 0x06, 0xa4, 0xea, 0x42,
        0x08, 0xda, 0xb4, 0x71, 0xb0, 0xcf, 0x12, 0x7a, 0x4e, 0xfa, 0x6c, 0x1d, 0x84, 0x00, 0xc8, 0x7f,
        0x91, 0x45, 0xaa, 0x2b, 0xc2, 0xb1, 0x8f, 0xd5, 0xba, 0xf2, 0xad, 0x19, 0xb2, 0x67, 0x36, 0xf7,
        0x0f, 0x0a, 0x92, 0x7d, 0xe3, 0x9d, 0xe9, 0x90, 0x3e, 0x23, 0x27, 0x66, 0x13, 0xec, 0x81, 0x15,
        0xbd, 0x22, 0xbf, 0x9f, 0x7e, 0xa9, 0x51, 0x4b, 0x4c, 0xfb, 0x02, 0xd3, 0x70, 0x86, 0x31, 0xe7,
        0x3b, 0x05, 0x03, 0x54, 0x60, 0x48, 0x65, 0x18, 0xd2, 0xcd, 0x5f, 0x32, 0x88, 0x0e, 0x35, 0xfd
    };

    EnvelopedDataHelper()
    {
    }

    String getBaseCipherName(ASN1ObjectIdentifier algorithm)
    {
        String name = (String)BASE_CIPHER_NAMES.get(algorithm);

        if (name == null)
        {
            return algorithm.getId();
        }

        return name;
    }

    static ExtendedDigest getPRF(AlgorithmIdentifier algID)
        throws OperatorCreationException
    {
        return ((BcDigestProvider)prfs.get(algID.getAlgorithm())).get(null);
    }

    static BufferedBlockCipher createCipher(ASN1ObjectIdentifier algorithm)
        throws CMSException
    {
        BlockCipher cipher;

        if (NISTObjectIdentifiers.id_aes128_CBC.equals(algorithm)
            || NISTObjectIdentifiers.id_aes192_CBC.equals(algorithm)
            || NISTObjectIdentifiers.id_aes256_CBC.equals(algorithm))
        {
            cipher = new CBCBlockCipher(new AESEngine());
        }
        else if (PKCSObjectIdentifiers.des_EDE3_CBC.equals(algorithm))
        {
            cipher = new CBCBlockCipher(new DESedeEngine());
        }
        else if (OIWObjectIdentifiers.desCBC.equals(algorithm))
        {
            cipher = new CBCBlockCipher(new DESEngine());
        }
        else if (PKCSObjectIdentifiers.RC2_CBC.equals(algorithm))
        {
            cipher = new CBCBlockCipher(new RC2Engine());
        }
        else if (MiscObjectIdentifiers.cast5CBC.equals(algorithm))
        {
            cipher = new CBCBlockCipher(new CAST5Engine());
        }
        else
        {
            throw new CMSException("cannot recognise cipher: " + algorithm);
        }

        return new PaddedBufferedBlockCipher(cipher, new PKCS7Padding());
    }

    static Wrapper createRFC3211Wrapper(ASN1ObjectIdentifier algorithm)
        throws CMSException
    {
        if (NISTObjectIdentifiers.id_aes128_CBC.equals(algorithm)
            || NISTObjectIdentifiers.id_aes192_CBC.equals(algorithm)
            || NISTObjectIdentifiers.id_aes256_CBC.equals(algorithm))
        {
            return new RFC3211WrapEngine(new AESEngine());
        }
        else if (PKCSObjectIdentifiers.des_EDE3_CBC.equals(algorithm))
        {
            return new RFC3211WrapEngine(new DESedeEngine());
        }
        else if (OIWObjectIdentifiers.desCBC.equals(algorithm))
        {
            return new RFC3211WrapEngine(new DESEngine());
        }
        else if (PKCSObjectIdentifiers.RC2_CBC.equals(algorithm))
        {
            return new RFC3211WrapEngine(new RC2Engine());
        }
        else
        {
            throw new CMSException("cannot recognise wrapper: " + algorithm);
        }
    }

    static Object createContentCipher(boolean forEncryption, CipherParameters encKey, AlgorithmIdentifier encryptionAlgID)
        throws CMSException
    {
        ASN1ObjectIdentifier encAlg = encryptionAlgID.getAlgorithm();

        if (encAlg.equals(PKCSObjectIdentifiers.rc4))
        {
            StreamCipher cipher = new RC4Engine();

            cipher.init(forEncryption, encKey);

            return cipher;
        }
        else
        {
            BufferedBlockCipher cipher = createCipher(encryptionAlgID.getAlgorithm());
            ASN1Primitive sParams = encryptionAlgID.getParameters().toASN1Primitive();

            if (sParams != null && !(sParams instanceof ASN1Null))
            {
                if (encAlg.equals(CMSAlgorithm.DES_EDE3_CBC)
                    || encAlg.equals(CMSAlgorithm.IDEA_CBC)
                    || encAlg.equals(CMSAlgorithm.AES128_CBC)
                    || encAlg.equals(CMSAlgorithm.AES192_CBC)
                    || encAlg.equals(CMSAlgorithm.AES256_CBC)
                    || encAlg.equals(CMSAlgorithm.CAMELLIA128_CBC)
                    || encAlg.equals(CMSAlgorithm.CAMELLIA192_CBC)
                    || encAlg.equals(CMSAlgorithm.CAMELLIA256_CBC)
                    || encAlg.equals(CMSAlgorithm.SEED_CBC)
                    || encAlg.equals(OIWObjectIdentifiers.desCBC))
                {
                    cipher.init(forEncryption, new ParametersWithIV(encKey,
                        ASN1OctetString.getInstance(sParams).getOctets()));
                }
                else if (encAlg.equals(CMSAlgorithm.CAST5_CBC))
                {
                    CAST5CBCParameters cbcParams = CAST5CBCParameters.getInstance(sParams);

                    cipher.init(forEncryption, new ParametersWithIV(encKey, cbcParams.getIV()));
                }
                else if (encAlg.equals(CMSAlgorithm.RC2_CBC))
                {
                    RC2CBCParameter cbcParams = RC2CBCParameter.getInstance(sParams);

                    cipher.init(forEncryption, new ParametersWithIV(new RC2Parameters(((KeyParameter)encKey).getKey(), rc2Ekb[cbcParams.getRC2ParameterVersion().intValue()]), cbcParams.getIV()));
                }
                else
                {
                    throw new CMSException("cannot match parameters");
                }
            }
            else
            {
                if (encAlg.equals(CMSAlgorithm.DES_EDE3_CBC)
                    || encAlg.equals(CMSAlgorithm.IDEA_CBC)
                    || encAlg.equals(CMSAlgorithm.CAST5_CBC))
                {
                    cipher.init(forEncryption, new ParametersWithIV(encKey, new byte[8]));
                }
                else
                {
                    cipher.init(forEncryption, encKey);
                }
            }

            return cipher;
        }
    }

    AlgorithmIdentifier generateAlgorithmIdentifier(ASN1ObjectIdentifier encryptionOID, CipherParameters encKey, SecureRandom random)
        throws CMSException
    {
        if (encryptionOID.equals(CMSAlgorithm.AES128_CBC)
                || encryptionOID.equals(CMSAlgorithm.AES192_CBC)
                || encryptionOID.equals(CMSAlgorithm.AES256_CBC)
                || encryptionOID.equals(CMSAlgorithm.CAMELLIA128_CBC)
                || encryptionOID.equals(CMSAlgorithm.CAMELLIA192_CBC)
                || encryptionOID.equals(CMSAlgorithm.CAMELLIA256_CBC)
                || encryptionOID.equals(CMSAlgorithm.SEED_CBC))
        {
            byte[] iv = new byte[16];

            random.nextBytes(iv);

            return new AlgorithmIdentifier(encryptionOID, new DEROctetString(iv));
        }
        else if (encryptionOID.equals(CMSAlgorithm.DES_EDE3_CBC)
                || encryptionOID.equals(CMSAlgorithm.IDEA_CBC)
                || encryptionOID.equals(OIWObjectIdentifiers.desCBC))
        {
            byte[] iv = new byte[8];

            random.nextBytes(iv);

            return new AlgorithmIdentifier(encryptionOID, new DEROctetString(iv));
        }
        else if (encryptionOID.equals(CMSAlgorithm.CAST5_CBC))
        {
            byte[] iv = new byte[8];

            random.nextBytes(iv);

            CAST5CBCParameters cbcParams = new CAST5CBCParameters(iv, ((KeyParameter)encKey).getKey().length * 8);

            return new AlgorithmIdentifier(encryptionOID, cbcParams);
        }
        else if (encryptionOID.equals(PKCSObjectIdentifiers.rc4))
        {
            return new AlgorithmIdentifier(encryptionOID, DERNull.INSTANCE);
        }
        else if (encryptionOID.equals(PKCSObjectIdentifiers.RC2_CBC))
        {
            byte[] iv = new byte[8];

            random.nextBytes(iv);

            RC2CBCParameter cbcParams = new RC2CBCParameter(rc2Table[128], iv);

            return new AlgorithmIdentifier(encryptionOID, cbcParams);
        }
        else
        {
            throw new CMSException("unable to match algorithm");
        }
    }

    CipherKeyGenerator createKeyGenerator(ASN1ObjectIdentifier algorithm, SecureRandom random)
        throws CMSException
    {
        if (NISTObjectIdentifiers.id_aes128_CBC.equals(algorithm))
        {
            return createCipherKeyGenerator(random, 128);
        }
        else if (NISTObjectIdentifiers.id_aes192_CBC.equals(algorithm))
        {
            return createCipherKeyGenerator(random, 192);
        }
        else if (NISTObjectIdentifiers.id_aes256_CBC.equals(algorithm))
        {
            return createCipherKeyGenerator(random, 256);
        }
        else if (PKCSObjectIdentifiers.des_EDE3_CBC.equals(algorithm))
        {
            DESedeKeyGenerator keyGen = new DESedeKeyGenerator();

            keyGen.init(new KeyGenerationParameters(random, 192));

            return keyGen;
        }
        else if (NTTObjectIdentifiers.id_camellia128_cbc.equals(algorithm))
        {
            return createCipherKeyGenerator(random, 128);
        }
        else if (NTTObjectIdentifiers.id_camellia192_cbc.equals(algorithm))
        {
            return createCipherKeyGenerator(random, 192);
        }
        else if (NTTObjectIdentifiers.id_camellia256_cbc.equals(algorithm))
        {
            return createCipherKeyGenerator(random, 256);
        }
        else if (KISAObjectIdentifiers.id_seedCBC.equals(algorithm))
        {
            return createCipherKeyGenerator(random, 128);
        }
        else if (CMSAlgorithm.CAST5_CBC.equals(algorithm))
        {
            return createCipherKeyGenerator(random, 128);
        }
        else if (OIWObjectIdentifiers.desCBC.equals(algorithm))
        {
            DESKeyGenerator keyGen = new DESKeyGenerator();

            keyGen.init(new KeyGenerationParameters(random, 64));

            return keyGen;
        }
        else if (PKCSObjectIdentifiers.rc4.equals(algorithm))
        {
            return createCipherKeyGenerator(random, 128);
        }
        else if (PKCSObjectIdentifiers.RC2_CBC.equals(algorithm))
        {
            return createCipherKeyGenerator(random, 128);
        }
        else
        {
            throw new CMSException("cannot recognise cipher: " + algorithm);
        }

    }

    private CipherKeyGenerator createCipherKeyGenerator(SecureRandom random, int keySize)
    {
        CipherKeyGenerator keyGen = new CipherKeyGenerator();

        keyGen.init(new KeyGenerationParameters(random, keySize));

        return keyGen;
    }
}
