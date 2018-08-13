package org.bouncycastle.jcajce.provider.asymmetric.util;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.agreement.kdf.DHKDFParameters;
import org.bouncycastle.crypto.agreement.kdf.DHKEKGenerator;
import org.bouncycastle.crypto.params.DESParameters;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Strings;

public abstract class BaseAgreementSpi
    extends KeyAgreementSpi
{
    private static final Map<String, ASN1ObjectIdentifier> defaultOids = new HashMap<String, ASN1ObjectIdentifier>();
    private static final Map<String, Integer> keySizes = new HashMap<String, Integer>();
    private static final Map<String, String> nameTable = new HashMap<String, String>();

    private static final Hashtable oids = new Hashtable();
    private static final Hashtable des = new Hashtable();

    static
    {
        Integer i64 = Integers.valueOf(64);
        Integer i128 = Integers.valueOf(128);
        Integer i192 = Integers.valueOf(192);
        Integer i256 = Integers.valueOf(256);

        keySizes.put("DES", i64);
        keySizes.put("DESEDE", i192);
        keySizes.put("BLOWFISH", i128);
        keySizes.put("AES", i256);

        keySizes.put(NISTObjectIdentifiers.id_aes128_ECB.getId(), i128);
        keySizes.put(NISTObjectIdentifiers.id_aes192_ECB.getId(), i192);
        keySizes.put(NISTObjectIdentifiers.id_aes256_ECB.getId(), i256);
        keySizes.put(NISTObjectIdentifiers.id_aes128_CBC.getId(), i128);
        keySizes.put(NISTObjectIdentifiers.id_aes192_CBC.getId(), i192);
        keySizes.put(NISTObjectIdentifiers.id_aes256_CBC.getId(), i256);
        keySizes.put(NISTObjectIdentifiers.id_aes128_CFB.getId(), i128);
        keySizes.put(NISTObjectIdentifiers.id_aes192_CFB.getId(), i192);
        keySizes.put(NISTObjectIdentifiers.id_aes256_CFB.getId(), i256);
        keySizes.put(NISTObjectIdentifiers.id_aes128_OFB.getId(), i128);
        keySizes.put(NISTObjectIdentifiers.id_aes192_OFB.getId(), i192);
        keySizes.put(NISTObjectIdentifiers.id_aes256_OFB.getId(), i256);
        keySizes.put(NISTObjectIdentifiers.id_aes128_wrap.getId(), i128);
        keySizes.put(NISTObjectIdentifiers.id_aes192_wrap.getId(), i192);
        keySizes.put(NISTObjectIdentifiers.id_aes256_wrap.getId(), i256);
        keySizes.put(NISTObjectIdentifiers.id_aes128_CCM.getId(), i128);
        keySizes.put(NISTObjectIdentifiers.id_aes192_CCM.getId(), i192);
        keySizes.put(NISTObjectIdentifiers.id_aes256_CCM.getId(), i256);
        keySizes.put(NISTObjectIdentifiers.id_aes128_GCM.getId(), i128);
        keySizes.put(NISTObjectIdentifiers.id_aes192_GCM.getId(), i192);
        keySizes.put(NISTObjectIdentifiers.id_aes256_GCM.getId(), i256);
        keySizes.put(NTTObjectIdentifiers.id_camellia128_wrap.getId(), i128);
        keySizes.put(NTTObjectIdentifiers.id_camellia192_wrap.getId(), i192);
        keySizes.put(NTTObjectIdentifiers.id_camellia256_wrap.getId(), i256);
        keySizes.put(KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap.getId(), i128);

        keySizes.put(PKCSObjectIdentifiers.id_alg_CMS3DESwrap.getId(), i192);
        keySizes.put(PKCSObjectIdentifiers.des_EDE3_CBC.getId(), i192);
        keySizes.put(OIWObjectIdentifiers.desCBC.getId(), i64);

        keySizes.put(CryptoProObjectIdentifiers.gostR28147_gcfb.getId(), i256);
        keySizes.put(CryptoProObjectIdentifiers.id_Gost28147_89_None_KeyWrap.getId(), i256);
        keySizes.put(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_KeyWrap.getId(), i256);

        keySizes.put(PKCSObjectIdentifiers.id_hmacWithSHA1.getId(), Integers.valueOf(160));
        keySizes.put(PKCSObjectIdentifiers.id_hmacWithSHA256.getId(), i256);
        keySizes.put(PKCSObjectIdentifiers.id_hmacWithSHA384.getId(), Integers.valueOf(384));
        keySizes.put(PKCSObjectIdentifiers.id_hmacWithSHA512.getId(), Integers.valueOf(512));

        defaultOids.put("DESEDE", PKCSObjectIdentifiers.des_EDE3_CBC);
        defaultOids.put("AES", NISTObjectIdentifiers.id_aes256_CBC);
        defaultOids.put("CAMELLIA", NTTObjectIdentifiers.id_camellia256_cbc);
        defaultOids.put("SEED", KISAObjectIdentifiers.id_seedCBC);
        defaultOids.put("DES", OIWObjectIdentifiers.desCBC);

        nameTable.put(MiscObjectIdentifiers.cast5CBC.getId(), "CAST5");
        nameTable.put(MiscObjectIdentifiers.as_sys_sec_alg_ideaCBC.getId(), "IDEA");
        nameTable.put(MiscObjectIdentifiers.cryptlib_algorithm_blowfish_ECB.getId(), "Blowfish");
        nameTable.put(MiscObjectIdentifiers.cryptlib_algorithm_blowfish_CBC.getId(), "Blowfish");
        nameTable.put(MiscObjectIdentifiers.cryptlib_algorithm_blowfish_CFB.getId(), "Blowfish");
        nameTable.put(MiscObjectIdentifiers.cryptlib_algorithm_blowfish_OFB.getId(), "Blowfish");
        nameTable.put(OIWObjectIdentifiers.desECB.getId(), "DES");
        nameTable.put(OIWObjectIdentifiers.desCBC.getId(), "DES");
        nameTable.put(OIWObjectIdentifiers.desCFB.getId(), "DES");
        nameTable.put(OIWObjectIdentifiers.desOFB.getId(), "DES");
        nameTable.put(OIWObjectIdentifiers.desEDE.getId(), "DESede");
        nameTable.put(PKCSObjectIdentifiers.des_EDE3_CBC.getId(), "DESede");
        nameTable.put(PKCSObjectIdentifiers.id_alg_CMS3DESwrap.getId(), "DESede");
        nameTable.put(PKCSObjectIdentifiers.id_alg_CMSRC2wrap.getId(), "RC2");
        nameTable.put(PKCSObjectIdentifiers.id_hmacWithSHA1.getId(), "HmacSHA1");
        nameTable.put(PKCSObjectIdentifiers.id_hmacWithSHA224.getId(), "HmacSHA224");
        nameTable.put(PKCSObjectIdentifiers.id_hmacWithSHA256.getId(), "HmacSHA256");
        nameTable.put(PKCSObjectIdentifiers.id_hmacWithSHA384.getId(), "HmacSHA384");
        nameTable.put(PKCSObjectIdentifiers.id_hmacWithSHA512.getId(), "HmacSHA512");
        nameTable.put(NTTObjectIdentifiers.id_camellia128_cbc.getId(), "Camellia");
        nameTable.put(NTTObjectIdentifiers.id_camellia192_cbc.getId(), "Camellia");
        nameTable.put(NTTObjectIdentifiers.id_camellia256_cbc.getId(), "Camellia");
        nameTable.put(NTTObjectIdentifiers.id_camellia128_wrap.getId(), "Camellia");
        nameTable.put(NTTObjectIdentifiers.id_camellia192_wrap.getId(), "Camellia");
        nameTable.put(NTTObjectIdentifiers.id_camellia256_wrap.getId(), "Camellia");
        nameTable.put(KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap.getId(), "SEED");
        nameTable.put(KISAObjectIdentifiers.id_seedCBC.getId(), "SEED");
        nameTable.put(KISAObjectIdentifiers.id_seedMAC.getId(), "SEED");
        nameTable.put(CryptoProObjectIdentifiers.gostR28147_gcfb.getId(), "GOST28147");

        nameTable.put(NISTObjectIdentifiers.id_aes128_wrap.getId(), "AES");
        nameTable.put(NISTObjectIdentifiers.id_aes128_CCM.getId(), "AES");
        nameTable.put(NISTObjectIdentifiers.id_aes128_CCM.getId(), "AES");

        oids.put("DESEDE", PKCSObjectIdentifiers.des_EDE3_CBC);
        oids.put("AES", NISTObjectIdentifiers.id_aes256_CBC);
        oids.put("DES", OIWObjectIdentifiers.desCBC);

        des.put("DES", "DES");
        des.put("DESEDE", "DES");
        des.put(OIWObjectIdentifiers.desCBC.getId(), "DES");
        des.put(PKCSObjectIdentifiers.des_EDE3_CBC.getId(), "DES");
        des.put(PKCSObjectIdentifiers.id_alg_CMS3DESwrap.getId(), "DES");
    }

    protected final String kaAlgorithm;
    protected final DerivationFunction kdf;

    protected byte[]     ukmParameters;

    public BaseAgreementSpi(String kaAlgorithm, DerivationFunction kdf)
    {
        this.kaAlgorithm = kaAlgorithm;
        this.kdf = kdf;
    }

    protected static String getAlgorithm(String algDetails)
    {
        if (algDetails.indexOf('[') > 0)
        {
            return algDetails.substring(0, algDetails.indexOf('['));
        }

        if (algDetails.startsWith(NISTObjectIdentifiers.aes.getId()))
        {
            return "AES";
        }
        if (algDetails.startsWith(GNUObjectIdentifiers.Serpent.getId()))
        {
            return "Serpent";
        }

        String name = (String)nameTable.get(Strings.toUpperCase(algDetails));

        if (name != null)
        {
            return name;
        }

        return algDetails;
    }

    protected static int getKeySize(String algDetails)
    {
        if (algDetails.indexOf('[') > 0)
        {
            return Integer.parseInt(algDetails.substring(algDetails.indexOf('[') + 1, algDetails.indexOf(']')));
        }

        String algKey = Strings.toUpperCase(algDetails);
        if (!keySizes.containsKey(algKey))
        {
            return -1;
        }

        return ((Integer)keySizes.get(algKey)).intValue();
    }

    protected static byte[] trimZeroes(byte[] secret)
    {
        if (secret[0] != 0)
        {
            return secret;
        }
        else
        {
            int ind = 0;
            while (ind < secret.length && secret[ind] == 0)
            {
                ind++;
            }

            byte[] rv = new byte[secret.length - ind];

            System.arraycopy(secret, ind, rv, 0, rv.length);

            return rv;
        }
    }

    protected byte[] engineGenerateSecret()
        throws IllegalStateException
    {
        if (kdf != null)
        {
            byte[] secret = calcSecret();
            try
            {
                return getSharedSecretBytes(secret, null, secret.length * 8);
            }
            catch (NoSuchAlgorithmException e)
            {
                throw new IllegalStateException(e.getMessage());
            }
        }

        return calcSecret();
    }

    protected int engineGenerateSecret(
        byte[]  sharedSecret,
        int     offset)
        throws IllegalStateException, ShortBufferException
    {
        byte[] secret = engineGenerateSecret();

        if (sharedSecret.length - offset < secret.length)
        {
            throw new ShortBufferException(kaAlgorithm + " key agreement: need " + secret.length + " bytes");
        }

        System.arraycopy(secret, 0, sharedSecret, offset, secret.length);

        return secret.length;
    }

    protected SecretKey engineGenerateSecret(
        String algorithm)
        throws NoSuchAlgorithmException
    {
        String algKey = Strings.toUpperCase(algorithm);
        String oidAlgorithm = algorithm;

        if (oids.containsKey(algKey))
        {
            oidAlgorithm = ((ASN1ObjectIdentifier)oids.get(algKey)).getId();
        }

        int    keySize = getKeySize(oidAlgorithm);

        byte[] secret = getSharedSecretBytes(calcSecret(), oidAlgorithm, keySize);

        String algName = getAlgorithm(algorithm);

        if (des.containsKey(algName))
        {
            DESParameters.setOddParity(secret);
        }

        return new SecretKeySpec(secret, algName);
    }

    private byte[] getSharedSecretBytes(byte[] secret, String oidAlgorithm, int keySize)
        throws NoSuchAlgorithmException
    {
        if (kdf != null)
        {
            if (keySize < 0)
            {
                throw new NoSuchAlgorithmException("unknown algorithm encountered: " + oidAlgorithm);
            }
            byte[] keyBytes = new byte[keySize / 8];

            if (kdf instanceof DHKEKGenerator)
            {
                if (oidAlgorithm == null)
                {
                    throw new NoSuchAlgorithmException("algorithm OID is null");
                }
                ASN1ObjectIdentifier oid;
                try
                {
                    oid = new ASN1ObjectIdentifier(oidAlgorithm);
                }
                catch (IllegalArgumentException e)
                {
                    throw new NoSuchAlgorithmException("no OID for algorithm: " + oidAlgorithm);
                }
                DHKDFParameters params = new DHKDFParameters(oid, keySize, secret, ukmParameters);

                kdf.init(params);
            }
            else
            {
                KDFParameters params = new KDFParameters(secret, ukmParameters);

                kdf.init(params);
            }

            kdf.generateBytes(keyBytes, 0, keyBytes.length);

            Arrays.clear(secret);

            return keyBytes;
        }
        else
        {
            if (keySize > 0)
            {
                byte[] keyBytes = new byte[keySize / 8];

                System.arraycopy(secret, 0, keyBytes, 0, keyBytes.length);

                Arrays.clear(secret);

                return keyBytes;
            }

            return secret;
        }
    }

    protected abstract byte[] calcSecret();
}
