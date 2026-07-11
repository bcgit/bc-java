package org.bouncycastle.operator;

import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.nsri.NSRIObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

/**
 * Catalogue of content-encryption algorithm OIDs used where code only needs to
 * identify the parameter form or block size family for an algorithm.
 * <p>
 * The methods in this class are membership tests only. They do not provide key
 * sizes, JCA names, or provider registration aliases.
 */
public final class OidCatalogue
{
    private static final Set<ASN1ObjectIdentifier> ccmAlgs = new HashSet<ASN1ObjectIdentifier>();
    private static final Set<ASN1ObjectIdentifier> gcmAlgs = new HashSet<ASN1ObjectIdentifier>();
    private static final Set<ASN1ObjectIdentifier> cbc128Algs = new HashSet<ASN1ObjectIdentifier>();
    private static final Set<ASN1ObjectIdentifier> cbc64Algs = new HashSet<ASN1ObjectIdentifier>();

    static
    {
        ccmAlgs.add(NISTObjectIdentifiers.id_aes128_CCM);
        ccmAlgs.add(NISTObjectIdentifiers.id_aes192_CCM);
        ccmAlgs.add(NISTObjectIdentifiers.id_aes256_CCM);
        ccmAlgs.add(NSRIObjectIdentifiers.id_aria128_ccm);
        ccmAlgs.add(NSRIObjectIdentifiers.id_aria192_ccm);
        ccmAlgs.add(NSRIObjectIdentifiers.id_aria256_ccm);
        ccmAlgs.add(GMObjectIdentifiers.sms4_ccm);

        gcmAlgs.add(NISTObjectIdentifiers.id_aes128_GCM);
        gcmAlgs.add(NISTObjectIdentifiers.id_aes192_GCM);
        gcmAlgs.add(NISTObjectIdentifiers.id_aes256_GCM);
        gcmAlgs.add(NSRIObjectIdentifiers.id_aria128_gcm);
        gcmAlgs.add(NSRIObjectIdentifiers.id_aria192_gcm);
        gcmAlgs.add(NSRIObjectIdentifiers.id_aria256_gcm);
        gcmAlgs.add(GMObjectIdentifiers.sms4_gcm);

        cbc128Algs.add(NISTObjectIdentifiers.id_aes128_CBC);
        cbc128Algs.add(NISTObjectIdentifiers.id_aes192_CBC);
        cbc128Algs.add(NISTObjectIdentifiers.id_aes256_CBC);
        cbc128Algs.add(NTTObjectIdentifiers.id_camellia128_cbc);
        cbc128Algs.add(NTTObjectIdentifiers.id_camellia192_cbc);
        cbc128Algs.add(NTTObjectIdentifiers.id_camellia256_cbc);
        cbc128Algs.add(KISAObjectIdentifiers.id_seedCBC);
        cbc128Algs.add(GMObjectIdentifiers.sms4_cbc);

        cbc64Algs.add(OIWObjectIdentifiers.desCBC);
        cbc64Algs.add(PKCSObjectIdentifiers.des_EDE3_CBC);
        cbc64Algs.add(PKCSObjectIdentifiers.RC2_CBC);
        cbc64Algs.add(MiscObjectIdentifiers.cast5CBC);
        cbc64Algs.add(MiscObjectIdentifiers.as_sys_sec_alg_ideaCBC);
    }

    private OidCatalogue()
    {

    }

    /**
     * Return whether the OID identifies a CCM content-encryption algorithm
     * whose parameters are encoded as CCMParameters.
     *
     * @param algorithm candidate algorithm OID.
     * @return true if the OID is a known CCM content-encryption algorithm.
     */
    public static boolean isCCM(ASN1ObjectIdentifier algorithm)
    {
        return ccmAlgs.contains(algorithm);
    }

    /**
     * Return whether the OID identifies a GCM content-encryption algorithm
     * whose parameters are encoded as GCMParameters.
     *
     * @param algorithm candidate algorithm OID.
     * @return true if the OID is a known GCM content-encryption algorithm.
     */
    public static boolean isGCM(ASN1ObjectIdentifier algorithm)
    {
        return gcmAlgs.contains(algorithm);
    }

    /**
     * Return whether the OID identifies a CBC content-encryption algorithm
     * with a 128-bit block size and an IV encoded as an octet string.
     *
     * @param algorithm candidate algorithm OID.
     * @return true if the OID is a known 128-bit block CBC content-encryption algorithm.
     */
    public static boolean isCBC128(ASN1ObjectIdentifier algorithm)
    {
        return cbc128Algs.contains(algorithm);
    }

    /**
     * Return whether the OID identifies a CBC content-encryption algorithm with a
     * 64-bit block size (DES, triple-DES, RC2, CAST5, IDEA).
     * <p>
     * This is a block-size predicate only: unlike the GCM/CCM/CBC-128 families, the
     * members do not share a single parameter encoding (RC2 carries RC2CBCParameter,
     * CAST5 carries CAST5CBCParameters, the rest an octet-string IV), so this test is
     * for code that classifies by block size (e.g. PKCS#7 padded output length) rather
     * than by parameter form.
     *
     * @param algorithm candidate algorithm OID.
     * @return true if the OID is a known 64-bit block CBC content-encryption algorithm.
     */
    public static boolean isCBC64(ASN1ObjectIdentifier algorithm)
    {
        return cbc64Algs.contains(algorithm);
    }

    /**
     * Return whether the OID identifies the ChaCha20-Poly1305 AEAD content-encryption
     * algorithm.
     *
     * @param algorithm candidate algorithm OID.
     * @return true if the OID is ChaCha20-Poly1305.
     */
    public static boolean isChaCha20Poly1305(ASN1ObjectIdentifier algorithm)
    {
        return PKCSObjectIdentifiers.id_alg_AEADChaCha20Poly1305.equals(algorithm);
    }

    /**
     * Return whether the OID identifies an AEAD content-encryption algorithm whose
     * parameters are encoded as GCMParameters or CCMParameters (i.e. a GCM or CCM
     * algorithm). ChaCha20-Poly1305, whose parameters differ, is not included here;
     * use {@link #isAuthEnveloped(ASN1ObjectIdentifier)} for the full set of algorithms
     * usable with CMS AuthEnvelopedData.
     *
     * @param algorithm candidate algorithm OID.
     * @return true if the OID is a known GCM or CCM content-encryption algorithm.
     */
    public static boolean isAEAD(ASN1ObjectIdentifier algorithm)
    {
        return isGCM(algorithm) || isCCM(algorithm);
    }

    /**
     * Return whether the OID identifies a content-encryption algorithm that provides
     * authenticated encryption and so can be used with CMS AuthEnvelopedData (RFC 5083):
     * the GCM and CCM families plus ChaCha20-Poly1305.
     *
     * @param algorithm candidate algorithm OID.
     * @return true if the OID is a known AEAD content-encryption algorithm.
     */
    public static boolean isAuthEnveloped(ASN1ObjectIdentifier algorithm)
    {
        return isAEAD(algorithm) || isChaCha20Poly1305(algorithm);
    }
}
