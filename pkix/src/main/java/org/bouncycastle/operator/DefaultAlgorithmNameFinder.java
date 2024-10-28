package org.bouncycastle.operator;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

public class DefaultAlgorithmNameFinder
    implements AlgorithmNameFinder
{
    private final static Map algorithms = new HashMap();

    private static void addAlgorithm(ASN1ObjectIdentifier algOid, String algorithmName)
    {
        if (algorithms.containsKey(algOid))
        {
            throw new IllegalStateException("algOid already present in addAlgorithm");
        }
        
        algorithms.put(algOid, algorithmName);
    }

    static
    {
        addAlgorithm(BSIObjectIdentifiers.ecdsa_plain_RIPEMD160, "RIPEMD160WITHPLAIN-ECDSA");
        addAlgorithm(BSIObjectIdentifiers.ecdsa_plain_SHA1, "SHA1WITHPLAIN-ECDSA");
        addAlgorithm(BSIObjectIdentifiers.ecdsa_plain_SHA224, "SHA224WITHPLAIN-ECDSA");
        addAlgorithm(BSIObjectIdentifiers.ecdsa_plain_SHA256, "SHA256WITHPLAIN-ECDSA");
        addAlgorithm(BSIObjectIdentifiers.ecdsa_plain_SHA384, "SHA384WITHPLAIN-ECDSA");
        addAlgorithm(BSIObjectIdentifiers.ecdsa_plain_SHA512, "SHA512WITHPLAIN-ECDSA");
        addAlgorithm(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001, "GOST3411WITHECGOST3410-2001");
        addAlgorithm(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94, "GOST3411WITHGOST3410-94");
        addAlgorithm(CryptoProObjectIdentifiers.gostR3411, "GOST3411");
        addAlgorithm(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256, "GOST3411WITHECGOST3410-2012-256");
        addAlgorithm(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512, "GOST3411WITHECGOST3410-2012-512");
        addAlgorithm(EACObjectIdentifiers.id_TA_ECDSA_SHA_1, "SHA1WITHCVC-ECDSA");
        addAlgorithm(EACObjectIdentifiers.id_TA_ECDSA_SHA_224, "SHA224WITHCVC-ECDSA");
        addAlgorithm(EACObjectIdentifiers.id_TA_ECDSA_SHA_256, "SHA256WITHCVC-ECDSA");
        addAlgorithm(EACObjectIdentifiers.id_TA_ECDSA_SHA_384, "SHA384WITHCVC-ECDSA");
        addAlgorithm(EACObjectIdentifiers.id_TA_ECDSA_SHA_512, "SHA512WITHCVC-ECDSA");
        addAlgorithm(BCObjectIdentifiers.falcon_512, "FALCON");
        addAlgorithm(BCObjectIdentifiers.falcon_1024, "FALCON");
        
        addAlgorithm(NISTObjectIdentifiers.id_ml_dsa_44, "ML-DSA-44");
        addAlgorithm(NISTObjectIdentifiers.id_ml_dsa_65, "ML-DSA-65");
        addAlgorithm(NISTObjectIdentifiers.id_ml_dsa_87, "ML-DSA-87");

        addAlgorithm(NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512, "ML-DSA-44-WITH-SHA512");
        addAlgorithm(NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512, "ML-DSA-65-WITH-SHA512");
        addAlgorithm(NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512, "ML-DSA-87-WITH-SHA512");

        addAlgorithm(NISTObjectIdentifiers.id_slh_dsa_sha2_128s, "SLH-DSA-SHA2-128S");
        addAlgorithm(NISTObjectIdentifiers.id_slh_dsa_sha2_128f, "SLH-DSA-SHA2-128F");
        addAlgorithm(NISTObjectIdentifiers.id_slh_dsa_sha2_192s, "SLH-DSA-SHA2-192S");
        addAlgorithm(NISTObjectIdentifiers.id_slh_dsa_sha2_192f, "SLH-DSA-SHA2-192F");
        addAlgorithm(NISTObjectIdentifiers.id_slh_dsa_sha2_256s, "SLH-DSA-SHA2-256S");
        addAlgorithm(NISTObjectIdentifiers.id_slh_dsa_sha2_256f, "SLH-DSA-SHA2-256F");
        addAlgorithm(NISTObjectIdentifiers.id_slh_dsa_shake_128s, "SLH-DSA-SHAKE-128S");
        addAlgorithm(NISTObjectIdentifiers.id_slh_dsa_shake_128f, "SLH-DSA-SHAKE-128F");
        addAlgorithm(NISTObjectIdentifiers.id_slh_dsa_shake_192s, "SLH-DSA-SHAKE-192S");
        addAlgorithm(NISTObjectIdentifiers.id_slh_dsa_shake_192f, "SLH-DSA-SHAKE-192F");
        addAlgorithm(NISTObjectIdentifiers.id_slh_dsa_shake_256s, "SLH-DSA-SHAKE-256S");
        addAlgorithm(NISTObjectIdentifiers.id_slh_dsa_shake_256f, "SLH-DSA-SHAKE-256F");

        addAlgorithm(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256, "SLH-DSA-SHA2-128S-WITH-SHA256");
        addAlgorithm(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256, "SLH-DSA-SHA2-128F-WITH-SHA256");
        addAlgorithm(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512, "SLH-DSA-SHA2-192S-WITH-SHA512");
        addAlgorithm(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512, "SLH-DSA-SHA2-192F-WITH-SHA512");
        addAlgorithm(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512, "SLH-DSA-SHA2-256S-WITH-SHA512");
        addAlgorithm(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512, "SLH-DSA-SHA2-256F-WITH-SHA512");
        addAlgorithm(NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128, "SLH-DSA-SHAKE-128S-WITH-SHAKE128");
        addAlgorithm(NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128, "SLH-DSA-SHAKE-128F-WITH-SHAKE128");
        addAlgorithm(NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256, "SLH-DSA-SHAKE-192S-WITH-SHAKE256");
        addAlgorithm(NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256, "SLH-DSA-SHAKE-192F-WITH-SHAKE256");
        addAlgorithm(NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256, "SLH-DSA-SHAKE-256S-WITH-SHAKE256");
        addAlgorithm(NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256, "SLH-DSA-SHAKE-256F-WITH-SHAKE256");

        addAlgorithm(BCObjectIdentifiers.sphincsPlus_sha2_128s_r3, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_sha2_128f_r3, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_shake_128s_r3, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_shake_128f_r3, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_haraka_128s_r3, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_haraka_128f_r3, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_sha2_192s_r3, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_sha2_192f_r3, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_shake_192s_r3, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_shake_192f_r3, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_haraka_192s_r3, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_haraka_192f_r3, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_sha2_256s_r3, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_sha2_256f_r3, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_shake_256s_r3, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_shake_256f_r3, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_haraka_256s_r3, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_haraka_256f_r3, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_sha2_128s_r3_simple, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_sha2_128f_r3_simple, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_shake_128s_r3_simple, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_shake_128f_r3_simple, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_haraka_128s_r3_simple, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_haraka_128f_r3_simple, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_sha2_192s_r3_simple, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_sha2_192f_r3_simple, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_shake_192s_r3_simple, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_shake_192f_r3_simple, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_haraka_192s_r3_simple, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_haraka_192f_r3_simple, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_sha2_256s_r3_simple, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_sha2_256f_r3_simple, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_shake_256s_r3_simple, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_shake_256f_r3_simple, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_haraka_256s_r3_simple, "SPHINCS+");
        addAlgorithm(BCObjectIdentifiers.sphincsPlus_haraka_256f_r3_simple, "SPHINCS+");

        addAlgorithm(NISTObjectIdentifiers.id_sha224, "SHA224");
        addAlgorithm(NISTObjectIdentifiers.id_sha256, "SHA256");
        addAlgorithm(NISTObjectIdentifiers.id_sha384, "SHA384");
        addAlgorithm(NISTObjectIdentifiers.id_sha512, "SHA512");
        addAlgorithm(NISTObjectIdentifiers.id_sha3_224, "SHA3-224");
        addAlgorithm(NISTObjectIdentifiers.id_sha3_256, "SHA3-256");
        addAlgorithm(NISTObjectIdentifiers.id_sha3_384, "SHA3-384");
        addAlgorithm(NISTObjectIdentifiers.id_sha3_512, "SHA3-512");
        addAlgorithm(OIWObjectIdentifiers.dsaWithSHA1, "SHA1WITHDSA");
        addAlgorithm(OIWObjectIdentifiers.elGamalAlgorithm, "ELGAMAL");
        addAlgorithm(OIWObjectIdentifiers.idSHA1, "SHA1");
        addAlgorithm(OIWObjectIdentifiers.md5WithRSA, "MD5WITHRSA");
        addAlgorithm(OIWObjectIdentifiers.sha1WithRSA, "SHA1WITHRSA");
        addAlgorithm(PKCSObjectIdentifiers.id_RSAES_OAEP, "RSAOAEP");
        addAlgorithm(PKCSObjectIdentifiers.id_RSASSA_PSS, "RSAPSS");
        addAlgorithm(PKCSObjectIdentifiers.md2WithRSAEncryption, "MD2WITHRSA");
        addAlgorithm(PKCSObjectIdentifiers.md5, "MD5");
        addAlgorithm(PKCSObjectIdentifiers.md5WithRSAEncryption, "MD5WITHRSA");
        addAlgorithm(PKCSObjectIdentifiers.rsaEncryption, "RSA");
        addAlgorithm(PKCSObjectIdentifiers.sha1WithRSAEncryption, "SHA1WITHRSA");
        addAlgorithm(PKCSObjectIdentifiers.sha224WithRSAEncryption, "SHA224WITHRSA");
        addAlgorithm(PKCSObjectIdentifiers.sha256WithRSAEncryption, "SHA256WITHRSA");
        addAlgorithm(PKCSObjectIdentifiers.sha384WithRSAEncryption, "SHA384WITHRSA");
        addAlgorithm(PKCSObjectIdentifiers.sha512WithRSAEncryption, "SHA512WITHRSA");
        addAlgorithm(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224, "SHA3-224WITHRSA");
        addAlgorithm(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256, "SHA3-256WITHRSA");
        addAlgorithm(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384, "SHA3-384WITHRSA");
        addAlgorithm(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512, "SHA3-512WITHRSA");
        addAlgorithm(TeleTrusTObjectIdentifiers.ripemd128, "RIPEMD128");
        addAlgorithm(TeleTrusTObjectIdentifiers.ripemd160, "RIPEMD160");
        addAlgorithm(TeleTrusTObjectIdentifiers.ripemd256, "RIPEMD256");
        addAlgorithm(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128, "RIPEMD128WITHRSA");
        addAlgorithm(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160, "RIPEMD160WITHRSA");
        addAlgorithm(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256, "RIPEMD256WITHRSA");
        addAlgorithm(X9ObjectIdentifiers.ecdsa_with_SHA1, "ECDSAWITHSHA1");
        addAlgorithm(X9ObjectIdentifiers.ecdsa_with_SHA224, "SHA224WITHECDSA");
        addAlgorithm(X9ObjectIdentifiers.ecdsa_with_SHA256, "SHA256WITHECDSA");
        addAlgorithm(X9ObjectIdentifiers.ecdsa_with_SHA384, "SHA384WITHECDSA");
        addAlgorithm(X9ObjectIdentifiers.ecdsa_with_SHA512, "SHA512WITHECDSA");
        addAlgorithm(NISTObjectIdentifiers.id_ecdsa_with_sha3_224, "SHA3-224WITHECDSA");
        addAlgorithm(NISTObjectIdentifiers.id_ecdsa_with_sha3_256, "SHA3-256WITHECDSA");
        addAlgorithm(NISTObjectIdentifiers.id_ecdsa_with_sha3_384, "SHA3-384WITHECDSA");
        addAlgorithm(NISTObjectIdentifiers.id_ecdsa_with_sha3_512, "SHA3-512WITHECDSA");
        addAlgorithm(X9ObjectIdentifiers.id_dsa_with_sha1, "SHA1WITHDSA");
        addAlgorithm(NISTObjectIdentifiers.dsa_with_sha224, "SHA224WITHDSA");
        addAlgorithm(NISTObjectIdentifiers.dsa_with_sha256, "SHA256WITHDSA");
        addAlgorithm(NISTObjectIdentifiers.dsa_with_sha384, "SHA384WITHDSA");
        addAlgorithm(NISTObjectIdentifiers.dsa_with_sha512, "SHA512WITHDSA");
        addAlgorithm(NISTObjectIdentifiers.id_dsa_with_sha3_224, "SHA3-224WITHDSA");
        addAlgorithm(NISTObjectIdentifiers.id_dsa_with_sha3_256, "SHA3-256WITHDSA");
        addAlgorithm(NISTObjectIdentifiers.id_dsa_with_sha3_384, "SHA3-384WITHDSA");
        addAlgorithm(NISTObjectIdentifiers.id_dsa_with_sha3_512, "SHA3-512WITHDSA");
        addAlgorithm(GNUObjectIdentifiers.Tiger_192, "Tiger");

        addAlgorithm(PKCSObjectIdentifiers.RC2_CBC, "RC2/CBC");
        addAlgorithm(PKCSObjectIdentifiers.des_EDE3_CBC, "DESEDE-3KEY/CBC");
        addAlgorithm(NISTObjectIdentifiers.id_aes128_ECB, "AES-128/ECB");
        addAlgorithm(NISTObjectIdentifiers.id_aes192_ECB, "AES-192/ECB");
        addAlgorithm(NISTObjectIdentifiers.id_aes256_ECB, "AES-256/ECB");
        addAlgorithm(NISTObjectIdentifiers.id_aes128_CBC, "AES-128/CBC");
        addAlgorithm(NISTObjectIdentifiers.id_aes192_CBC, "AES-192/CBC");
        addAlgorithm(NISTObjectIdentifiers.id_aes256_CBC, "AES-256/CBC");
        addAlgorithm(NISTObjectIdentifiers.id_aes128_CFB, "AES-128/CFB");
        addAlgorithm(NISTObjectIdentifiers.id_aes192_CFB, "AES-192/CFB");
        addAlgorithm(NISTObjectIdentifiers.id_aes256_CFB, "AES-256/CFB");
        addAlgorithm(NISTObjectIdentifiers.id_aes128_OFB, "AES-128/OFB");
        addAlgorithm(NISTObjectIdentifiers.id_aes192_OFB, "AES-192/OFB");
        addAlgorithm(NISTObjectIdentifiers.id_aes256_OFB, "AES-256/OFB");
        addAlgorithm(NTTObjectIdentifiers.id_camellia128_cbc, "CAMELLIA-128/CBC");
        addAlgorithm(NTTObjectIdentifiers.id_camellia192_cbc, "CAMELLIA-192/CBC");
        addAlgorithm(NTTObjectIdentifiers.id_camellia256_cbc, "CAMELLIA-256/CBC");
        addAlgorithm(KISAObjectIdentifiers.id_seedCBC, "SEED/CBC");
        addAlgorithm(MiscObjectIdentifiers.as_sys_sec_alg_ideaCBC, "IDEA/CBC");
        addAlgorithm(MiscObjectIdentifiers.cast5CBC, "CAST5/CBC");
        addAlgorithm(MiscObjectIdentifiers.cryptlib_algorithm_blowfish_ECB, "Blowfish/ECB");
        addAlgorithm(MiscObjectIdentifiers.cryptlib_algorithm_blowfish_CBC, "Blowfish/CBC");
        addAlgorithm(MiscObjectIdentifiers.cryptlib_algorithm_blowfish_CFB, "Blowfish/CFB");
        addAlgorithm(MiscObjectIdentifiers.cryptlib_algorithm_blowfish_OFB, "Blowfish/OFB");
        addAlgorithm(GNUObjectIdentifiers.Serpent_128_ECB, "Serpent-128/ECB");
        addAlgorithm(GNUObjectIdentifiers.Serpent_128_CBC, "Serpent-128/CBC");
        addAlgorithm(GNUObjectIdentifiers.Serpent_128_CFB, "Serpent-128/CFB");
        addAlgorithm(GNUObjectIdentifiers.Serpent_128_OFB, "Serpent-128/OFB");
        addAlgorithm(GNUObjectIdentifiers.Serpent_192_ECB, "Serpent-192/ECB");
        addAlgorithm(GNUObjectIdentifiers.Serpent_192_CBC, "Serpent-192/CBC");
        addAlgorithm(GNUObjectIdentifiers.Serpent_192_CFB, "Serpent-192/CFB");
        addAlgorithm(GNUObjectIdentifiers.Serpent_192_OFB, "Serpent-192/OFB");
        addAlgorithm(GNUObjectIdentifiers.Serpent_256_ECB, "Serpent-256/ECB");
        addAlgorithm(GNUObjectIdentifiers.Serpent_256_CBC, "Serpent-256/CBC");
        addAlgorithm(GNUObjectIdentifiers.Serpent_256_CFB, "Serpent-256/CFB");
        addAlgorithm(GNUObjectIdentifiers.Serpent_256_OFB, "Serpent-256/OFB");
        addAlgorithm(MiscObjectIdentifiers.id_blake2b160, "BLAKE2b-160");
        addAlgorithm(MiscObjectIdentifiers.id_blake2b256, "BLAKE2b-256");
        addAlgorithm(MiscObjectIdentifiers.id_blake2b384, "BLAKE2b-384");
        addAlgorithm(MiscObjectIdentifiers.id_blake2b512, "BLAKE2b-512");
        addAlgorithm(MiscObjectIdentifiers.id_blake2s128, "BLAKE2s-128");
        addAlgorithm(MiscObjectIdentifiers.id_blake2s160, "BLAKE2s-160");
        addAlgorithm(MiscObjectIdentifiers.id_blake2s224, "BLAKE2s-224");
        addAlgorithm(MiscObjectIdentifiers.id_blake2s256, "BLAKE2s-256");
        addAlgorithm(MiscObjectIdentifiers.blake3_256, "BLAKE3-256");
    }

    public boolean hasAlgorithmName(ASN1ObjectIdentifier objectIdentifier)
    {
        return algorithms.containsKey(objectIdentifier);
    }

    public String getAlgorithmName(ASN1ObjectIdentifier objectIdentifier)
    {
        String name = (String)algorithms.get(objectIdentifier);

        return (name != null) ? name : objectIdentifier.getId();
    }

    public String getAlgorithmName(AlgorithmIdentifier algorithmIdentifier)
    {
        // TODO: take into account PSS/OAEP params
        return getAlgorithmName(algorithmIdentifier.getAlgorithm());
    }

    public Set<ASN1ObjectIdentifier> getOIDSet()
    {
        return algorithms.keySet();
    }
}
