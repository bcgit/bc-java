package org.bouncycastle.operator;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.util.Strings;

public class DefaultSignatureAlgorithmIdentifierFinder
    implements SignatureAlgorithmIdentifierFinder
{
    private static Map algorithms = new HashMap();
    private static Set noParams = new HashSet();
    private static Map params = new HashMap();
    private static Set pkcs15RsaEncryption = new HashSet();
    private static Map digestOids = new HashMap();

    private static final ASN1ObjectIdentifier ENCRYPTION_RSA = PKCSObjectIdentifiers.rsaEncryption;
    private static final ASN1ObjectIdentifier ENCRYPTION_DSA = X9ObjectIdentifiers.id_dsa_with_sha1;
    private static final ASN1ObjectIdentifier ENCRYPTION_ECDSA = X9ObjectIdentifiers.ecdsa_with_SHA1;
    private static final ASN1ObjectIdentifier ENCRYPTION_RSA_PSS = PKCSObjectIdentifiers.id_RSASSA_PSS;
    private static final ASN1ObjectIdentifier ENCRYPTION_GOST3410 = CryptoProObjectIdentifiers.gostR3410_94;
    private static final ASN1ObjectIdentifier ENCRYPTION_ECGOST3410 = CryptoProObjectIdentifiers.gostR3410_2001;

    static
    {
        algorithms.put("MD2WITHRSAENCRYPTION", PKCSObjectIdentifiers.md2WithRSAEncryption);
        algorithms.put("MD2WITHRSA", PKCSObjectIdentifiers.md2WithRSAEncryption);
        algorithms.put("MD5WITHRSAENCRYPTION", PKCSObjectIdentifiers.md5WithRSAEncryption);
        algorithms.put("MD5WITHRSA", PKCSObjectIdentifiers.md5WithRSAEncryption);
        algorithms.put("SHA1WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha1WithRSAEncryption);
        algorithms.put("SHA1WITHRSA", PKCSObjectIdentifiers.sha1WithRSAEncryption);
        algorithms.put("SHA224WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha224WithRSAEncryption);
        algorithms.put("SHA224WITHRSA", PKCSObjectIdentifiers.sha224WithRSAEncryption);
        algorithms.put("SHA256WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha256WithRSAEncryption);
        algorithms.put("SHA256WITHRSA", PKCSObjectIdentifiers.sha256WithRSAEncryption);
        algorithms.put("SHA384WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha384WithRSAEncryption);
        algorithms.put("SHA384WITHRSA", PKCSObjectIdentifiers.sha384WithRSAEncryption);
        algorithms.put("SHA512WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha512WithRSAEncryption);
        algorithms.put("SHA512WITHRSA", PKCSObjectIdentifiers.sha512WithRSAEncryption);
        algorithms.put("SHA1WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA224WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA256WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA384WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA512WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("RIPEMD160WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160);
        algorithms.put("RIPEMD160WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160);
        algorithms.put("RIPEMD128WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128);
        algorithms.put("RIPEMD128WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128);
        algorithms.put("RIPEMD256WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256);
        algorithms.put("RIPEMD256WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256);
        algorithms.put("SHA1WITHDSA", X9ObjectIdentifiers.id_dsa_with_sha1);
        algorithms.put("DSAWITHSHA1", X9ObjectIdentifiers.id_dsa_with_sha1);
        algorithms.put("SHA224WITHDSA", NISTObjectIdentifiers.dsa_with_sha224);
        algorithms.put("SHA256WITHDSA", NISTObjectIdentifiers.dsa_with_sha256);
        algorithms.put("SHA384WITHDSA", NISTObjectIdentifiers.dsa_with_sha384);
        algorithms.put("SHA512WITHDSA", NISTObjectIdentifiers.dsa_with_sha512);
        algorithms.put("SHA1WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA1);
        algorithms.put("ECDSAWITHSHA1", X9ObjectIdentifiers.ecdsa_with_SHA1);
        algorithms.put("SHA224WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA224);
        algorithms.put("SHA256WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA256);
        algorithms.put("SHA384WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA384);
        algorithms.put("SHA512WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA512);
        algorithms.put("GOST3411WITHGOST3410", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94);
        algorithms.put("GOST3411WITHGOST3410-94", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94);
        algorithms.put("GOST3411WITHECGOST3410", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001);
        algorithms.put("GOST3411WITHECGOST3410-2001", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001);
        algorithms.put("GOST3411WITHGOST3410-2001", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001);
        algorithms.put("SHA1WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA1);
        algorithms.put("SHA224WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA224);
        algorithms.put("SHA256WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA256);
        algorithms.put("SHA384WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA384);
        algorithms.put("SHA512WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA512);
        algorithms.put("RIPEMD160WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_RIPEMD160);
        algorithms.put("SHA1WITHCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_1);
        algorithms.put("SHA224WITHCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_224);
        algorithms.put("SHA256WITHCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_256);
        algorithms.put("SHA384WITHCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_384);
        algorithms.put("SHA512WITHCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_512);
        algorithms.put("SHA3-512WITHSPHINCS256", BCObjectIdentifiers.sphincs256_with_SHA3_512);
        algorithms.put("SHA512WITHSPHINCS256", BCObjectIdentifiers.sphincs256_with_SHA512);

        //
        // According to RFC 3279, the ASN.1 encoding SHALL (id-dsa-with-sha1) or MUST (ecdsa-with-SHA*) omit the parameters field.
        // The parameters field SHALL be NULL for RSA based signature algorithms.
        //
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA1);
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA224);
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA256);
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA384);
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA512);
        noParams.add(X9ObjectIdentifiers.id_dsa_with_sha1);
        noParams.add(NISTObjectIdentifiers.dsa_with_sha224);
        noParams.add(NISTObjectIdentifiers.dsa_with_sha256);
        noParams.add(NISTObjectIdentifiers.dsa_with_sha384);
        noParams.add(NISTObjectIdentifiers.dsa_with_sha512);

        //
        // RFC 4491
        //
        noParams.add(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94);
        noParams.add(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001);

        //
        // SPHINCS-256
        //
        noParams.add(BCObjectIdentifiers.sphincs256_with_SHA512);
        noParams.add(BCObjectIdentifiers.sphincs256_with_SHA3_512);

        //
        // PKCS 1.5 encrypted  algorithms
        //
        pkcs15RsaEncryption.add(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        pkcs15RsaEncryption.add(PKCSObjectIdentifiers.sha224WithRSAEncryption);
        pkcs15RsaEncryption.add(PKCSObjectIdentifiers.sha256WithRSAEncryption);
        pkcs15RsaEncryption.add(PKCSObjectIdentifiers.sha384WithRSAEncryption);
        pkcs15RsaEncryption.add(PKCSObjectIdentifiers.sha512WithRSAEncryption);
        pkcs15RsaEncryption.add(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128);
        pkcs15RsaEncryption.add(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160);
        pkcs15RsaEncryption.add(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256);

        //
        // explicit params
        //
        AlgorithmIdentifier sha1AlgId = new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE);
        params.put("SHA1WITHRSAANDMGF1", createPSSParams(sha1AlgId, 20));

        AlgorithmIdentifier sha224AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha224, DERNull.INSTANCE);
        params.put("SHA224WITHRSAANDMGF1", createPSSParams(sha224AlgId, 28));

        AlgorithmIdentifier sha256AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
        params.put("SHA256WITHRSAANDMGF1", createPSSParams(sha256AlgId, 32));

        AlgorithmIdentifier sha384AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384, DERNull.INSTANCE);
        params.put("SHA384WITHRSAANDMGF1", createPSSParams(sha384AlgId, 48));

        AlgorithmIdentifier sha512AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512, DERNull.INSTANCE);
        params.put("SHA512WITHRSAANDMGF1", createPSSParams(sha512AlgId, 64));

        //
        // digests
        //
        digestOids.put(PKCSObjectIdentifiers.sha224WithRSAEncryption, NISTObjectIdentifiers.id_sha224);
        digestOids.put(PKCSObjectIdentifiers.sha256WithRSAEncryption, NISTObjectIdentifiers.id_sha256);
        digestOids.put(PKCSObjectIdentifiers.sha384WithRSAEncryption, NISTObjectIdentifiers.id_sha384);
        digestOids.put(PKCSObjectIdentifiers.sha512WithRSAEncryption, NISTObjectIdentifiers.id_sha512);
        digestOids.put(PKCSObjectIdentifiers.md2WithRSAEncryption, PKCSObjectIdentifiers.md2);
        digestOids.put(PKCSObjectIdentifiers.md4WithRSAEncryption, PKCSObjectIdentifiers.md4);
        digestOids.put(PKCSObjectIdentifiers.md5WithRSAEncryption, PKCSObjectIdentifiers.md5);
        digestOids.put(PKCSObjectIdentifiers.sha1WithRSAEncryption, OIWObjectIdentifiers.idSHA1);
        digestOids.put(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128, TeleTrusTObjectIdentifiers.ripemd128);
        digestOids.put(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160, TeleTrusTObjectIdentifiers.ripemd160);
        digestOids.put(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256, TeleTrusTObjectIdentifiers.ripemd256);
        digestOids.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94, CryptoProObjectIdentifiers.gostR3411);
        digestOids.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001, CryptoProObjectIdentifiers.gostR3411);
    }

    private static AlgorithmIdentifier generate(String signatureAlgorithm)
    {
        AlgorithmIdentifier sigAlgId;
        AlgorithmIdentifier encAlgId;
        AlgorithmIdentifier digAlgId;

        String algorithmName = Strings.toUpperCase(signatureAlgorithm);
        ASN1ObjectIdentifier sigOID = (ASN1ObjectIdentifier)algorithms.get(algorithmName);
        if (sigOID == null)
        {
            throw new IllegalArgumentException("Unknown signature type requested: " + algorithmName);
        }

        if (noParams.contains(sigOID))
        {
            sigAlgId = new AlgorithmIdentifier(sigOID);
        }
        else if (params.containsKey(algorithmName))
        {
            sigAlgId = new AlgorithmIdentifier(sigOID, (ASN1Encodable)params.get(algorithmName));
        }
        else
        {
            sigAlgId = new AlgorithmIdentifier(sigOID, DERNull.INSTANCE);
        }

        if (pkcs15RsaEncryption.contains(sigOID))
        {
            encAlgId = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
        }
        else
        {
            encAlgId = sigAlgId;
        }

        if (sigAlgId.getAlgorithm().equals(PKCSObjectIdentifiers.id_RSASSA_PSS))
        {
            digAlgId = ((RSASSAPSSparams)sigAlgId.getParameters()).getHashAlgorithm();
        }
        else
        {
            digAlgId = new AlgorithmIdentifier((ASN1ObjectIdentifier)digestOids.get(sigOID), DERNull.INSTANCE);
        }

        return sigAlgId;
    }

    private static RSASSAPSSparams createPSSParams(AlgorithmIdentifier hashAlgId, int saltSize)
    {
        return new RSASSAPSSparams(
            hashAlgId,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, hashAlgId),
            new ASN1Integer(saltSize),
            new ASN1Integer(1));
    }

    public AlgorithmIdentifier find(String sigAlgName)
    {
        return generate(sigAlgName);
    }
}