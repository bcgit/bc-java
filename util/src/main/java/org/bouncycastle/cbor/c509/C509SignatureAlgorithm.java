package org.bouncycastle.cbor.c509;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.util.Integers;

/**
 * The C509 Signature Algorithms Registry, Section 8.14 of
 * draft-ietf-cose-cbor-encoded-cert-20. Each registered CBOR int value stands for a
 * complete X.509 AlgorithmIdentifier, including its parameters, so conversion in
 * either direction is an exact table lookup.
 * <p>
 * Note the draft's Figure 18 prints the DER for values 23-25 with an inconsistent
 * SEQUENCE length octet (0x0B against 13 content octets); the entries here are built
 * from the OID object model and encode with the correct 0x0D, matching real
 * certificates and the value -256 row.
 */
public final class C509SignatureAlgorithm
{
    /** RSASSA-PKCS1-v1_5 with SHA-1 (1.2.840.113549.1.1.5). */
    public static final int RSASSA_PKCS1_V15_WITH_SHA1 = -256;
    /** ECDSA with SHA-1 (1.2.840.10045.4.1). */
    public static final int ECDSA_WITH_SHA1 = -255;
    /** ECDSA with SHA-256 (1.2.840.10045.4.3.2). */
    public static final int ECDSA_WITH_SHA256 = 0;
    /** ECDSA with SHA-384 (1.2.840.10045.4.3.3). */
    public static final int ECDSA_WITH_SHA384 = 1;
    /** ECDSA with SHA-512 (1.2.840.10045.4.3.4). */
    public static final int ECDSA_WITH_SHA512 = 2;
    /** ECDSA with SHAKE128 (1.3.6.1.5.5.7.6.32). */
    public static final int ECDSA_WITH_SHAKE128 = 3;
    /** ECDSA with SHAKE256 (1.3.6.1.5.5.7.6.33). */
    public static final int ECDSA_WITH_SHAKE256 = 4;
    /** Unsigned (1.3.6.1.5.5.7.6.36). */
    public static final int UNSIGNED = 5;
    /** SM2 with SM3 (1.2.156.10197.1.501). */
    public static final int SM2_WITH_SM3 = 8;
    /** Ed25519 (1.3.101.112). */
    public static final int ED25519 = 12;
    /** Ed448 (1.3.101.113). */
    public static final int ED448 = 13;
    /** RFC 6955 proof-of-possession with SHA-256 and HMAC-SHA256 (1.3.6.1.5.5.7.6.26). */
    public static final int ECDH_POP_SHA256_HMAC_SHA256 = 14;
    /** RFC 6955 proof-of-possession with SHA-384 and HMAC-SHA384 (1.3.6.1.5.5.7.6.27). */
    public static final int ECDH_POP_SHA384_HMAC_SHA384 = 15;
    /** RFC 6955 proof-of-possession with SHA-512 and HMAC-SHA512 (1.3.6.1.5.5.7.6.28). */
    public static final int ECDH_POP_SHA512_HMAC_SHA512 = 16;
    /** RSASSA-PKCS1-v1_5 with SHA-256 (1.2.840.113549.1.1.11). */
    public static final int RSASSA_PKCS1_V15_WITH_SHA256 = 23;
    /** RSASSA-PKCS1-v1_5 with SHA-384 (1.2.840.113549.1.1.12). */
    public static final int RSASSA_PKCS1_V15_WITH_SHA384 = 24;
    /** RSASSA-PKCS1-v1_5 with SHA-512 (1.2.840.113549.1.1.13). */
    public static final int RSASSA_PKCS1_V15_WITH_SHA512 = 25;
    /** RSASSA-PSS with SHA-256, MGF-1 with SHA-256 and a 32 octet salt (1.2.840.113549.1.1.10). */
    public static final int RSASSA_PSS_WITH_SHA256 = 26;
    /** RSASSA-PSS with SHA-384, MGF-1 with SHA-384 and a 48 octet salt (1.2.840.113549.1.1.10). */
    public static final int RSASSA_PSS_WITH_SHA384 = 27;
    /** RSASSA-PSS with SHA-512, MGF-1 with SHA-512 and a 64 octet salt (1.2.840.113549.1.1.10). */
    public static final int RSASSA_PSS_WITH_SHA512 = 28;
    /** RSASSA-PSS with SHAKE128 (1.3.6.1.5.5.7.6.30). */
    public static final int RSASSA_PSS_WITH_SHAKE128 = 29;
    /** RSASSA-PSS with SHAKE256 (1.3.6.1.5.5.7.6.31). */
    public static final int RSASSA_PSS_WITH_SHAKE256 = 30;

    private static final Map<Integer, AlgorithmIdentifier> codeToAlgorithm =
        new HashMap<Integer, AlgorithmIdentifier>();
    private static final Map<AlgorithmIdentifier, Integer> algorithmToCode =
        new HashMap<AlgorithmIdentifier, Integer>();

    private static void register(int code, AlgorithmIdentifier algorithm)
    {
        Integer boxed = Integers.valueOf(code);
        if (codeToAlgorithm.put(boxed, algorithm) != null || algorithmToCode.put(algorithm, boxed) != null)
        {
            throw new IllegalStateException("duplicate registry entry: " + code);
        }
    }

    private static void registerV15(int code, ASN1ObjectIdentifier sigOid)
    {
        register(code, new AlgorithmIdentifier(sigOid, DERNull.INSTANCE));
    }

    private static void registerPSS(int code, ASN1ObjectIdentifier digestOid, int saltLength)
    {
        AlgorithmIdentifier digest = new AlgorithmIdentifier(digestOid, DERNull.INSTANCE);
        register(code, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS,
            new RSASSAPSSparams(digest, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, digest),
                new ASN1Integer(saltLength), RSASSAPSSparams.DEFAULT_TRAILER_FIELD)));
    }

    static
    {
        registerV15(RSASSA_PKCS1_V15_WITH_SHA1, PKCSObjectIdentifiers.sha1WithRSAEncryption);
        register(ECDSA_WITH_SHA1, new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA1));
        register(ECDSA_WITH_SHA256, new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256));
        register(ECDSA_WITH_SHA384, new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA384));
        register(ECDSA_WITH_SHA512, new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA512));
        register(ECDSA_WITH_SHAKE128, new AlgorithmIdentifier(X509ObjectIdentifiers.id_ecdsa_with_shake128));
        register(ECDSA_WITH_SHAKE256, new AlgorithmIdentifier(X509ObjectIdentifiers.id_ecdsa_with_shake256));
        register(UNSIGNED, new AlgorithmIdentifier(IANAObjectIdentifiers.id_alg_unsigned));
        register(SM2_WITH_SM3, new AlgorithmIdentifier(GMObjectIdentifiers.sm2sign_with_sm3));
        register(ED25519, new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519));
        register(ED448, new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448));
        register(ECDH_POP_SHA256_HMAC_SHA256,
            new AlgorithmIdentifier(X509ObjectIdentifiers.pkix_algorithms.branch("26")));
        register(ECDH_POP_SHA384_HMAC_SHA384,
            new AlgorithmIdentifier(X509ObjectIdentifiers.pkix_algorithms.branch("27")));
        register(ECDH_POP_SHA512_HMAC_SHA512,
            new AlgorithmIdentifier(X509ObjectIdentifiers.pkix_algorithms.branch("28")));
        registerV15(RSASSA_PKCS1_V15_WITH_SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption);
        registerV15(RSASSA_PKCS1_V15_WITH_SHA384, PKCSObjectIdentifiers.sha384WithRSAEncryption);
        registerV15(RSASSA_PKCS1_V15_WITH_SHA512, PKCSObjectIdentifiers.sha512WithRSAEncryption);
        registerPSS(RSASSA_PSS_WITH_SHA256, NISTObjectIdentifiers.id_sha256, 32);
        registerPSS(RSASSA_PSS_WITH_SHA384, NISTObjectIdentifiers.id_sha384, 48);
        registerPSS(RSASSA_PSS_WITH_SHA512, NISTObjectIdentifiers.id_sha512, 64);
        register(RSASSA_PSS_WITH_SHAKE128, new AlgorithmIdentifier(X509ObjectIdentifiers.id_rsassa_pss_shake128));
        register(RSASSA_PSS_WITH_SHAKE256, new AlgorithmIdentifier(X509ObjectIdentifiers.id_rsassa_pss_shake256));
    }

    /**
     * Return the AlgorithmIdentifier a registered value stands for, or null if the
     * value is not registered.
     */
    public static AlgorithmIdentifier getAlgorithmIdentifier(int value)
    {
        return codeToAlgorithm.get(Integers.valueOf(value));
    }

    /**
     * Return the registered value for an AlgorithmIdentifier, matching its complete
     * encoding including parameters, or null if it is not registered.
     */
    public static Integer getValue(AlgorithmIdentifier algorithm)
    {
        return algorithmToCode.get(algorithm);
    }

    /**
     * Return true if the value identifies an algorithm whose signature value is an
     * ECDSA style pair of integers, encoded in C509 as a fixed width r || s byte
     * string in the manner of Section 2.1 of RFC 9053 (see Section 3.2.2 of the
     * draft). This covers the ECDSA values and SM2 with SM3.
     */
    public static boolean isEcdsaFormat(int value)
    {
        switch (value)
        {
        case ECDSA_WITH_SHA1:
        case ECDSA_WITH_SHA256:
        case ECDSA_WITH_SHA384:
        case ECDSA_WITH_SHA512:
        case ECDSA_WITH_SHAKE128:
        case ECDSA_WITH_SHAKE256:
        case SM2_WITH_SM3:
            return true;
        default:
            return false;
        }
    }

    private C509SignatureAlgorithm()
    {
    }
}
