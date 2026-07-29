package org.bouncycastle.cbor.c509;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.util.Integers;

/**
 * The C509 Extensions Registry, Section 8.8 of draft-ietf-cose-cbor-encoded-cert-20.
 * <p>
 * In an int-coded extension the absolute value of the int is the registered extension
 * value and the sign carries criticality: negative for critical, positive for
 * non-critical (Section 3.1.10).
 */
public final class C509ExtensionType
{
    /** Subject Key Identifier (2.5.29.14). */
    public static final int SUBJECT_KEY_IDENTIFIER = 1;
    /** Key Usage (2.5.29.15). */
    public static final int KEY_USAGE = 2;
    /** Subject Alternative Name (2.5.29.17). */
    public static final int SUBJECT_ALT_NAME = 3;
    /** Basic Constraints (2.5.29.19). */
    public static final int BASIC_CONSTRAINTS = 4;
    /** CRL Distribution Points (2.5.29.31). */
    public static final int CRL_DISTRIBUTION_POINTS = 5;
    /** Certificate Policies (2.5.29.32). */
    public static final int CERTIFICATE_POLICIES = 6;
    /** Authority Key Identifier (2.5.29.35). */
    public static final int AUTHORITY_KEY_IDENTIFIER = 7;
    /** Extended Key Usage (2.5.29.37). */
    public static final int EXTENDED_KEY_USAGE = 8;
    /** Authority Information Access (1.3.6.1.5.5.7.1.1). */
    public static final int AUTHORITY_INFO_ACCESS = 9;
    /** Subject Directory Attributes (2.5.29.9). */
    public static final int SUBJECT_DIRECTORY_ATTRIBUTES = 24;
    /** Issuer Alternative Name (2.5.29.18). */
    public static final int ISSUER_ALT_NAME = 25;
    /** Name Constraints (2.5.29.30). */
    public static final int NAME_CONSTRAINTS = 26;
    /** Policy Mappings (2.5.29.33). */
    public static final int POLICY_MAPPINGS = 27;
    /** Policy Constraints (2.5.29.36). */
    public static final int POLICY_CONSTRAINTS = 28;
    /** Freshest CRL (2.5.29.46). */
    public static final int FRESHEST_CRL = 29;
    /** Inhibit anyPolicy (2.5.29.54). */
    public static final int INHIBIT_ANY_POLICY = 30;
    /** Subject Information Access (1.3.6.1.5.5.7.1.11). */
    public static final int SUBJECT_INFO_ACCESS = 31;
    /** IPAddrBlocks (1.3.6.1.5.5.7.1.7), RFC 3779. */
    public static final int IP_ADDR_BLOCKS = 32;
    /** AS Identifiers (1.3.6.1.5.5.7.1.8), RFC 3779. */
    public static final int AS_IDENTIFIERS = 33;
    /** IPAddrBlocks v2 (1.3.6.1.5.5.7.1.28), RFC 8360. */
    public static final int IP_ADDR_BLOCKS_V2 = 34;
    /** AS Identifiers v2 (1.3.6.1.5.5.7.1.29), RFC 8360. */
    public static final int AS_IDENTIFIERS_V2 = 35;
    /** OCSP No Check (1.3.6.1.5.5.7.48.1.5), RFC 6960. */
    public static final int OCSP_NO_CHECK = 36;
    /** TLS Features (1.3.6.1.5.5.7.1.24), RFC 7633. */
    public static final int TLS_FEATURES = 38;

    private static final Map<Integer, ASN1ObjectIdentifier> codeToOid = new HashMap<Integer, ASN1ObjectIdentifier>();
    private static final Map<ASN1ObjectIdentifier, Integer> oidToCode = new HashMap<ASN1ObjectIdentifier, Integer>();

    private static void register(int code, ASN1ObjectIdentifier oid)
    {
        Integer boxed = Integers.valueOf(code);
        if (codeToOid.put(boxed, oid) != null || oidToCode.put(oid, boxed) != null)
        {
            throw new IllegalStateException("duplicate registry entry: " + code);
        }
    }

    static
    {
        register(SUBJECT_KEY_IDENTIFIER, Extension.subjectKeyIdentifier);
        register(KEY_USAGE, Extension.keyUsage);
        register(SUBJECT_ALT_NAME, Extension.subjectAlternativeName);
        register(BASIC_CONSTRAINTS, Extension.basicConstraints);
        register(CRL_DISTRIBUTION_POINTS, Extension.cRLDistributionPoints);
        register(CERTIFICATE_POLICIES, Extension.certificatePolicies);
        register(AUTHORITY_KEY_IDENTIFIER, Extension.authorityKeyIdentifier);
        register(EXTENDED_KEY_USAGE, Extension.extendedKeyUsage);
        register(AUTHORITY_INFO_ACCESS, Extension.authorityInfoAccess);
        register(SUBJECT_DIRECTORY_ATTRIBUTES, Extension.subjectDirectoryAttributes);
        register(ISSUER_ALT_NAME, Extension.issuerAlternativeName);
        register(NAME_CONSTRAINTS, Extension.nameConstraints);
        register(POLICY_MAPPINGS, Extension.policyMappings);
        register(POLICY_CONSTRAINTS, Extension.policyConstraints);
        register(FRESHEST_CRL, Extension.freshestCRL);
        register(INHIBIT_ANY_POLICY, Extension.inhibitAnyPolicy);
        register(SUBJECT_INFO_ACCESS, Extension.subjectInfoAccess);
        register(IP_ADDR_BLOCKS, X509ObjectIdentifiers.id_pe.branch("7"));
        register(AS_IDENTIFIERS, X509ObjectIdentifiers.id_pe.branch("8"));
        register(IP_ADDR_BLOCKS_V2, X509ObjectIdentifiers.id_pe.branch("28"));
        register(AS_IDENTIFIERS_V2, X509ObjectIdentifiers.id_pe.branch("29"));
        register(OCSP_NO_CHECK, OCSPObjectIdentifiers.id_pkix_ocsp_nocheck);
        register(TLS_FEATURES, X509ObjectIdentifiers.id_pe.branch("24"));
    }

    /**
     * Return the extension object identifier a registered value stands for, or null if
     * the value is not registered.
     */
    public static ASN1ObjectIdentifier getOID(int value)
    {
        return codeToOid.get(Integers.valueOf(value));
    }

    /**
     * Return the registered value for an extension object identifier, or null if it is
     * not registered.
     */
    public static Integer getValue(ASN1ObjectIdentifier oid)
    {
        return oidToCode.get(oid);
    }

    private C509ExtensionType()
    {
    }
}
