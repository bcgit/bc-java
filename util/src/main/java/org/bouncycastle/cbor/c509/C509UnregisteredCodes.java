package org.bouncycastle.cbor.c509;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.util.Longs;

/**
 * Stand-in object identifiers for C509 integer codes that have no entry in the
 * registries of draft-ietf-cose-cbor-encoded-cert-21 Section 8, and so no object
 * identifier of their own.
 * <p>
 * The RDN attribute, extension, certificate policy, extended key usage and
 * certification request attribute registries take values of up to 63 bits, with the
 * ranges above the registered ones set aside for private and future use. A natively
 * signed (type 2) certificate or certification request may carry such a value, but the
 * ASN.1 types this package presents its contents through (X500Name, Extensions,
 * KeyPurposeId, PolicyInformation) are keyed on object identifiers. Each unregistered
 * code is therefore given a stand-in object identifier in the Bouncy Castle arc
 * {@link BCObjectIdentifiers#bc_c509}, one sub-arc per registry (RDN attributes 1,
 * extensions 2, certificate policies 3, extended key usages 4, certification request
 * attributes 5): a code N &gt;= 0 is { arc 0 N } and a code N &lt; 0 is { arc 1 -(N + 1) }.
 * <p>
 * The stand-ins apply to natively signed structures only. In one, an unregistered int
 * is read as its stand-in and a stand-in is written as its int; an extension or
 * certification request attribute under a stand-in has the CBOR item that followed the
 * int as its value, uninterpreted. A CBOR re-encoded X.509 structure (type 3) cannot
 * carry an unregistered code, as there is no X.509 form to reconstruct, and a stand-in
 * met while converting from X.509 is treated as any other unknown object identifier.
 * <p>
 * Two things follow from a code being unregistered: nothing checks that it was the one
 * intended, and the object identifier reported for it changes should a later revision
 * of the registry assign it.
 */
public final class C509UnregisteredCodes
{
    // one sub-arc per registry, as laid out against BCObjectIdentifiers.bc_c509
    static final ASN1ObjectIdentifier RDN_ATTRIBUTE = BCObjectIdentifiers.bc_c509.branch("1");
    static final ASN1ObjectIdentifier EXTENSION = BCObjectIdentifiers.bc_c509.branch("2");
    static final ASN1ObjectIdentifier CERTIFICATE_POLICY = BCObjectIdentifiers.bc_c509.branch("3");
    static final ASN1ObjectIdentifier EXTENDED_KEY_USAGE = BCObjectIdentifiers.bc_c509.branch("4");
    static final ASN1ObjectIdentifier CR_ATTRIBUTE = BCObjectIdentifiers.bc_c509.branch("5");

    private static final BigInteger LONG_MAX = BigInteger.valueOf(Long.MAX_VALUE);

    private C509UnregisteredCodes()
    {
    }

    /**
     * Return the stand-in for an unregistered C509 RDN Attributes Registry value.
     *
     * @param code the registry value, 0 to 2^63 - 1.
     * @throws IllegalArgumentException if the value is out of range or is registered.
     */
    public static ASN1ObjectIdentifier rdnAttributeType(long code)
    {
        if (code < 0)
        {
            throw new IllegalArgumentException("C509 RDN attribute value out of range: " + code);
        }
        checkUnregistered(C509AttributeType.getOID(code) != null, "RDN attribute", code);
        return toOID(RDN_ATTRIBUTE, code);
    }

    /**
     * Return the stand-in for an unregistered C509 Extensions Registry value.
     *
     * @param code the registry value, 1 to 2^63 - 1.
     * @throws IllegalArgumentException if the value is out of range or is registered.
     */
    public static ASN1ObjectIdentifier extensionID(long code)
    {
        if (code < 1)
        {
            throw new IllegalArgumentException("C509 extension value out of range: " + code);
        }
        checkUnregistered(C509ExtensionType.getOID(code) != null, "extension", code);
        return toOID(EXTENSION, code);
    }

    /**
     * Return the stand-in for an unregistered C509 Certificate Policies Registry value.
     *
     * @throws IllegalArgumentException if the value is registered.
     */
    public static ASN1ObjectIdentifier certificatePolicy(long code)
    {
        checkUnregistered(C509ExtensionValueCodec.isRegisteredPolicy(code), "certificate policy", code);
        return toOID(CERTIFICATE_POLICY, code);
    }

    /**
     * Return the stand-in for an unregistered C509 Extended Key Usages Registry value.
     *
     * @throws IllegalArgumentException if the value is registered.
     */
    public static ASN1ObjectIdentifier extendedKeyUsage(long code)
    {
        checkUnregistered(C509ExtensionValueCodec.isRegisteredExtendedKeyUsage(code), "extended key usage", code);
        return toOID(EXTENDED_KEY_USAGE, code);
    }

    /**
     * Return the stand-in for an unregistered C509 CR Attributes Registry value.
     *
     * @throws IllegalArgumentException if the value is registered.
     */
    public static ASN1ObjectIdentifier crAttributeType(long code)
    {
        checkUnregistered(C509Attribute.isRegistered(code), "CR attribute", code);
        return toOID(CR_ATTRIBUTE, code);
    }

    /**
     * Return true if the object identifier is a stand-in for an unregistered code of
     * any of the registries.
     */
    public static boolean isUnregisteredCode(ASN1ObjectIdentifier oid)
    {
        return oid.on(BCObjectIdentifiers.bc_c509);
    }

    /**
     * Return the integer code a stand-in object identifier represents.
     *
     * @throws IllegalArgumentException if the object identifier is not a well-formed
     *         stand-in.
     */
    public static long getCode(ASN1ObjectIdentifier oid)
    {
        ASN1ObjectIdentifier[] arcs = {
            RDN_ATTRIBUTE, EXTENSION,
            CERTIFICATE_POLICY, EXTENDED_KEY_USAGE,
            CR_ATTRIBUTE };
        try
        {
            for (int i = 0; i != arcs.length; i++)
            {
                Long code = codeOf(arcs[i], oid);
                if (code != null)
                {
                    return code.longValue();
                }
            }
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException(e.getMessage());
        }
        throw new IllegalArgumentException("not a C509 unregistered code identifier: " + oid);
    }

    private static void checkUnregistered(boolean registered, String registry, long code)
    {
        if (registered)
        {
            throw new IllegalArgumentException("C509 " + registry + " value " + code + " is registered");
        }
    }

    static ASN1ObjectIdentifier toOID(ASN1ObjectIdentifier arc, long code)
    {
        if (code >= 0)
        {
            return arc.branch("0").branch(Long.toString(code));
        }
        return arc.branch("1").branch(Long.toString(-(code + 1)));
    }

    /**
     * Return the code a stand-in in the given registry arc represents, or null if the
     * object identifier is not in that arc.
     *
     * @throws IOException if the object identifier is in the arc but is not of the
     *         form { arc 0 N } or { arc 1 N } with N at most 2^63 - 1.
     */
    static Long codeOf(ASN1ObjectIdentifier arc, ASN1ObjectIdentifier oid)
        throws IOException
    {
        if (!oid.on(arc))
        {
            return null;
        }
        String tail = oid.getId().substring(arc.getId().length() + 1);
        int dot = tail.indexOf('.');
        if (dot == 1 && tail.indexOf('.', dot + 1) < 0)
        {
            char sign = tail.charAt(0);
            BigInteger magnitude = new BigInteger(tail.substring(dot + 1));
            if ((sign == '0' || sign == '1') && magnitude.compareTo(LONG_MAX) <= 0)
            {
                long value = magnitude.longValue();
                return Longs.valueOf(sign == '0' ? value : -value - 1);
            }
        }
        throw new IOException("malformed C509 unregistered code identifier: " + oid);
    }

    /**
     * In a natively signed structure a stand-in has one encoding, its int.
     */
    static void checkNotStandIn(boolean nativeForm, ASN1ObjectIdentifier oid)
        throws IOException
    {
        if (nativeForm && isUnregisteredCode(oid))
        {
            throw new IOException("C509 unregistered code identifier " + oid + " must be encoded as its int");
        }
    }
}
