package org.bouncycastle.cbor.c509;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.anssi.ANSSIObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.util.Integers;

/**
 * The C509 Public Key Algorithms Registry, Section 8.15 of
 * draft-ietf-cose-cbor-encoded-cert-20. Each registered CBOR int value stands for a
 * complete X.509 AlgorithmIdentifier, including its parameters (for the elliptic
 * curve entries the named curve is part of the parameters), so conversion in either
 * direction is an exact table lookup.
 */
public final class C509PublicKeyAlgorithm
{
    /** rsaEncryption (1.2.840.113549.1.1.1); subjectPublicKey encoded as in Section 3.2.1. */
    public static final int RSA = 0;
    /** id-ecPublicKey (1.2.840.10045.2.1) on secp256r1; subjectPublicKey encoded as in Section 3.2.1. */
    public static final int EC_SECP256R1 = 1;
    /** id-ecPublicKey (1.2.840.10045.2.1) on secp384r1. */
    public static final int EC_SECP384R1 = 2;
    /** id-ecPublicKey (1.2.840.10045.2.1) on secp521r1. */
    public static final int EC_SECP521R1 = 3;
    /** id-ecPublicKey (1.2.840.10045.2.1) on sm2p256v1. */
    public static final int EC_SM2P256V1 = 6;
    /** id-X25519 (1.3.101.110). */
    public static final int X25519 = 8;
    /** id-X448 (1.3.101.111). */
    public static final int X448 = 9;
    /** id-Ed25519 (1.3.101.112). */
    public static final int ED25519 = 12;
    /** id-Ed448 (1.3.101.113). */
    public static final int ED448 = 13;
    /** id-ecPublicKey (1.2.840.10045.2.1) on brainpoolP256r1. */
    public static final int EC_BRAINPOOLP256R1 = 24;
    /** id-ecPublicKey (1.2.840.10045.2.1) on brainpoolP384r1. */
    public static final int EC_BRAINPOOLP384R1 = 25;
    /** id-ecPublicKey (1.2.840.10045.2.1) on brainpoolP512r1. */
    public static final int EC_BRAINPOOLP512R1 = 26;
    /** id-ecPublicKey (1.2.840.10045.2.1) on FRP256v1. */
    public static final int EC_FRP256V1 = 27;

    private static final Map<Integer, AlgorithmIdentifier> codeToAlgorithm =
        new HashMap<Integer, AlgorithmIdentifier>();
    private static final Map<AlgorithmIdentifier, Integer> algorithmToCode =
        new HashMap<AlgorithmIdentifier, Integer>();
    private static final Map<Integer, ASN1ObjectIdentifier> codeToCurve =
        new HashMap<Integer, ASN1ObjectIdentifier>();

    private static void register(int code, AlgorithmIdentifier algorithm)
    {
        Integer boxed = Integers.valueOf(code);
        if (codeToAlgorithm.put(boxed, algorithm) != null || algorithmToCode.put(algorithm, boxed) != null)
        {
            throw new IllegalStateException("duplicate registry entry: " + code);
        }
    }

    private static void registerEC(int code, ASN1ObjectIdentifier namedCurve)
    {
        register(code, new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, namedCurve));
        codeToCurve.put(Integers.valueOf(code), namedCurve);
    }

    static
    {
        register(RSA, new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE));
        registerEC(EC_SECP256R1, SECObjectIdentifiers.secp256r1);
        registerEC(EC_SECP384R1, SECObjectIdentifiers.secp384r1);
        registerEC(EC_SECP521R1, SECObjectIdentifiers.secp521r1);
        registerEC(EC_SM2P256V1, GMObjectIdentifiers.sm2p256v1);
        register(X25519, new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519));
        register(X448, new AlgorithmIdentifier(EdECObjectIdentifiers.id_X448));
        register(ED25519, new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519));
        register(ED448, new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448));
        registerEC(EC_BRAINPOOLP256R1, TeleTrusTObjectIdentifiers.brainpoolP256r1);
        registerEC(EC_BRAINPOOLP384R1, TeleTrusTObjectIdentifiers.brainpoolP384r1);
        registerEC(EC_BRAINPOOLP512R1, TeleTrusTObjectIdentifiers.brainpoolP512r1);
        registerEC(EC_FRP256V1, ANSSIObjectIdentifiers.FRP256v1);
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
     * Return true if the value identifies an id-ecPublicKey algorithm carrying a
     * Weierstrass form point, to which the point compression of Section 3.2.1 applies.
     */
    public static boolean isWeierstrassPoint(int value)
    {
        return codeToCurve.containsKey(Integers.valueOf(value));
    }

    /**
     * Return the named curve object identifier for a Weierstrass form entry, or null
     * for any other value.
     */
    public static ASN1ObjectIdentifier getCurveOID(int value)
    {
        return codeToCurve.get(Integers.valueOf(value));
    }

    private C509PublicKeyAlgorithm()
    {
    }
}
