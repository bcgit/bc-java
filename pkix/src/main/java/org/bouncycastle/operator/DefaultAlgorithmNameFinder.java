package org.bouncycastle.operator;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cms.CMSEnvelopedGenerator;

public class DefaultAlgorithmNameFinder
    implements AlgorithmNameFinder
{
    private final static Map algorithms = new HashMap();

    static
    {
        algorithms.put(BSIObjectIdentifiers.ecdsa_plain_RIPEMD160, "RIPEMD160WITHPLAIN-ECDSA");
        algorithms.put(BSIObjectIdentifiers.ecdsa_plain_SHA1, "SHA1WITHPLAIN-ECDSA");
        algorithms.put(BSIObjectIdentifiers.ecdsa_plain_SHA224, "SHA224WITHPLAIN-ECDSA");
        algorithms.put(BSIObjectIdentifiers.ecdsa_plain_SHA256, "SHA256WITHPLAIN-ECDSA");
        algorithms.put(BSIObjectIdentifiers.ecdsa_plain_SHA384, "SHA384WITHPLAIN-ECDSA");
        algorithms.put(BSIObjectIdentifiers.ecdsa_plain_SHA512, "SHA512WITHPLAIN-ECDSA");
        algorithms.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001, "GOST3411WITHECGOST3410");
        algorithms.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001, "GOST3411WITHECGOST3410-2001");
        algorithms.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001, "GOST3411WITHGOST3410-2001");
        algorithms.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94, "GOST3411WITHGOST3410");
        algorithms.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94, "GOST3411WITHGOST3410-94");
        algorithms.put(CryptoProObjectIdentifiers.gostR3411, "GOST3411");
        algorithms.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_1, "SHA1WITHCVC-ECDSA");
        algorithms.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_224, "SHA224WITHPCVC-ECDSA");
        algorithms.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_256, "SHA256WITHCVC-ECDSA");
        algorithms.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_384, "SHA384WITHCVC-ECDSA");
        algorithms.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_512, "SHA512WITHCVC-ECDSA");
        algorithms.put(NISTObjectIdentifiers.dsa_with_sha224, "SHA224WITHDSA");
        algorithms.put(NISTObjectIdentifiers.dsa_with_sha256, "SHA256WITHDSA");
        algorithms.put(NISTObjectIdentifiers.dsa_with_sha384, "SHA384WITHDSA");
        algorithms.put(NISTObjectIdentifiers.dsa_with_sha512, "SHA512WITHDSA");
        algorithms.put(NISTObjectIdentifiers.id_sha224, "SHA224");
        algorithms.put(NISTObjectIdentifiers.id_sha256, "SHA256");
        algorithms.put(NISTObjectIdentifiers.id_sha384, "SHA384");
        algorithms.put(NISTObjectIdentifiers.id_sha512, "SHA512");
        algorithms.put(OIWObjectIdentifiers.elGamalAlgorithm, "ELGAMAL");
        algorithms.put(OIWObjectIdentifiers.idSHA1, "SHA1");
        algorithms.put(OIWObjectIdentifiers.md5WithRSA, "MD5WITHRSA");
        algorithms.put(OIWObjectIdentifiers.sha1WithRSA, "SHA1WITHRSA");
        algorithms.put(PKCSObjectIdentifiers.id_RSAES_OAEP, "RSAOAEP");
        algorithms.put(PKCSObjectIdentifiers.id_RSASSA_PSS, "RSAPSS");
        algorithms.put(PKCSObjectIdentifiers.md2WithRSAEncryption, "MD2WITHRSA");
        algorithms.put(PKCSObjectIdentifiers.md5, "MD5");
        algorithms.put(PKCSObjectIdentifiers.md5WithRSAEncryption, "MD5WITHRSA");
        algorithms.put(PKCSObjectIdentifiers.rsaEncryption, "RSA");
        algorithms.put(PKCSObjectIdentifiers.sha1WithRSAEncryption, "SHA1WITHRSA");
        algorithms.put(PKCSObjectIdentifiers.sha224WithRSAEncryption, "SHA224WITHRSA");
        algorithms.put(PKCSObjectIdentifiers.sha256WithRSAEncryption, "SHA256WITHRSA");
        algorithms.put(PKCSObjectIdentifiers.sha384WithRSAEncryption, "SHA384WITHRSA");
        algorithms.put(PKCSObjectIdentifiers.sha512WithRSAEncryption, "SHA512WITHRSA");
        algorithms.put(TeleTrusTObjectIdentifiers.ripemd128, "RIPEMD128");
        algorithms.put(TeleTrusTObjectIdentifiers.ripemd160, "RIPEMD160");
        algorithms.put(TeleTrusTObjectIdentifiers.ripemd256, "RIPEMD256");
        algorithms.put(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128, "RIPEMD128WITHRSA");
        algorithms.put(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160, "RIPEMD160WITHRSA");
        algorithms.put(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256, "RIPEMD256WITHRSA");
        algorithms.put(X9ObjectIdentifiers.ecdsa_with_SHA1, "ECDSAWITHSHA1");
        algorithms.put(X9ObjectIdentifiers.ecdsa_with_SHA1, "SHA1WITHECDSA");
        algorithms.put(X9ObjectIdentifiers.ecdsa_with_SHA224, "SHA224WITHECDSA");
        algorithms.put(X9ObjectIdentifiers.ecdsa_with_SHA256, "SHA256WITHECDSA");
        algorithms.put(X9ObjectIdentifiers.ecdsa_with_SHA384, "SHA384WITHECDSA");
        algorithms.put(X9ObjectIdentifiers.ecdsa_with_SHA512, "SHA512WITHECDSA");
        algorithms.put(X9ObjectIdentifiers.id_dsa_with_sha1, "SHA1WITHDSA");

        algorithms.put(PKCSObjectIdentifiers.RC2_CBC, "RC2/CBC");
        algorithms.put(PKCSObjectIdentifiers.des_EDE3_CBC, "DESEDE-3KEY/CBC");
        algorithms.put(NISTObjectIdentifiers.id_aes128_ECB, "AES-128/ECB");
        algorithms.put(NISTObjectIdentifiers.id_aes192_ECB, "AES-192/ECB");
        algorithms.put(NISTObjectIdentifiers.id_aes256_ECB, "AES-256/ECB");
        algorithms.put(NISTObjectIdentifiers.id_aes128_CBC, "AES-128/CBC");
        algorithms.put(NISTObjectIdentifiers.id_aes192_CBC, "AES-192/CBC");
        algorithms.put(NISTObjectIdentifiers.id_aes256_CBC, "AES-256/CBC");
        algorithms.put(NTTObjectIdentifiers.id_camellia128_cbc, "CAMELLIA-128/CBC");
        algorithms.put(NTTObjectIdentifiers.id_camellia192_cbc, "CAMELLIA-128/CBC");
        algorithms.put(NTTObjectIdentifiers.id_camellia256_cbc, "CAMELLIA-128/CBC");
        algorithms.put(KISAObjectIdentifiers.id_seedCBC, "SEED/CBC");
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
}
