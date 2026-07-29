package org.bouncycastle.cbor.c509;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.util.Integers;

/**
 * The C509 RDN Attributes Registry, Section 8.6 of draft-ietf-cose-cbor-encoded-cert-20.
 * <p>
 * In an int-coded RDN attribute the absolute value of the int is the registered
 * attribute value and the sign carries the DER string type: positive for utf8String,
 * negative for printableString. Attributes whose ASN.1 type is always IA5String
 * (emailAddress and domainComponent) are represented with a non-negative int
 * (Section 3.1.4).
 */
public final class C509AttributeType
{
    /** Email Address (1.2.840.113549.1.9.1), always IA5String. */
    public static final int EMAIL_ADDRESS = 0;
    /** Common Name (2.5.4.3). */
    public static final int COMMON_NAME = 1;
    /** Surname (2.5.4.4). */
    public static final int SURNAME = 2;
    /** Serial Number (2.5.4.5). */
    public static final int SERIAL_NUMBER = 3;
    /** Country (2.5.4.6). */
    public static final int COUNTRY = 4;
    /** Locality (2.5.4.7). */
    public static final int LOCALITY = 5;
    /** State or Province (2.5.4.8). */
    public static final int STATE_OR_PROVINCE = 6;
    /** Street Address (2.5.4.9). */
    public static final int STREET_ADDRESS = 7;
    /** Organization (2.5.4.10). */
    public static final int ORGANIZATION = 8;
    /** Organizational Unit (2.5.4.11). */
    public static final int ORGANIZATIONAL_UNIT = 9;
    /** Title (2.5.4.12). */
    public static final int TITLE = 10;
    /** Business Category (2.5.4.15). */
    public static final int BUSINESS_CATEGORY = 11;
    /** Postal Code (2.5.4.17). */
    public static final int POSTAL_CODE = 12;
    /** Given Name (2.5.4.42). */
    public static final int GIVEN_NAME = 13;
    /** Initials (2.5.4.43). */
    public static final int INITIALS = 14;
    /** Generation Qualifier (2.5.4.44). */
    public static final int GENERATION_QUALIFIER = 15;
    /** DN Qualifier (2.5.4.46). */
    public static final int DN_QUALIFIER = 16;
    /** Pseudonym (2.5.4.65). */
    public static final int PSEUDONYM = 17;
    /** Organization Identifier (2.5.4.97). */
    public static final int ORGANIZATION_IDENTIFIER = 18;
    /** Jurisdiction Locality Name (1.3.6.1.4.1.311.60.2.1.1). */
    public static final int JURISDICTION_LOCALITY_NAME = 19;
    /** Jurisdiction State or Province (1.3.6.1.4.1.311.60.2.1.2). */
    public static final int JURISDICTION_STATE_OR_PROVINCE = 20;
    /** Jurisdiction Country Name (1.3.6.1.4.1.311.60.2.1.3). */
    public static final int JURISDICTION_COUNTRY_NAME = 21;
    /** Domain Component (0.9.2342.19200300.100.1.25), always IA5String. */
    public static final int DOMAIN_COMPONENT = 22;
    /** Name (2.5.4.41). */
    public static final int NAME = 25;
    /** Telephone Number (2.5.4.20). */
    public static final int TELEPHONE_NUMBER = 26;
    /** Directory Management Domain Name (2.5.4.54). */
    public static final int DMD_NAME = 27;
    /** userid (0.9.2342.19200300.100.1.1). */
    public static final int UID = 28;
    /** Unstructured Name (1.2.840.113549.1.9.2). */
    public static final int UNSTRUCTURED_NAME = 29;
    /** Unstructured Address (1.2.840.113549.1.9.8). */
    public static final int UNSTRUCTURED_ADDRESS = 30;

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
        register(EMAIL_ADDRESS, BCStyle.EmailAddress);
        register(COMMON_NAME, BCStyle.CN);
        register(SURNAME, BCStyle.SURNAME);
        register(SERIAL_NUMBER, BCStyle.SERIALNUMBER);
        register(COUNTRY, BCStyle.C);
        register(LOCALITY, BCStyle.L);
        register(STATE_OR_PROVINCE, BCStyle.ST);
        register(STREET_ADDRESS, BCStyle.STREET);
        register(ORGANIZATION, BCStyle.O);
        register(ORGANIZATIONAL_UNIT, BCStyle.OU);
        register(TITLE, BCStyle.T);
        register(BUSINESS_CATEGORY, BCStyle.BUSINESS_CATEGORY);
        register(POSTAL_CODE, BCStyle.POSTAL_CODE);
        register(GIVEN_NAME, BCStyle.GIVENNAME);
        register(INITIALS, BCStyle.INITIALS);
        register(GENERATION_QUALIFIER, BCStyle.GENERATION);
        register(DN_QUALIFIER, BCStyle.DN_QUALIFIER);
        register(PSEUDONYM, BCStyle.PSEUDONYM);
        register(ORGANIZATION_IDENTIFIER, BCStyle.ORGANIZATION_IDENTIFIER);
        register(JURISDICTION_LOCALITY_NAME, BCStyle.JURISDICTION_L);
        register(JURISDICTION_STATE_OR_PROVINCE, BCStyle.JURISDICTION_ST);
        register(JURISDICTION_COUNTRY_NAME, BCStyle.JURISDICTION_C);
        register(DOMAIN_COMPONENT, BCStyle.DC);
        register(NAME, BCStyle.NAME);
        register(TELEPHONE_NUMBER, BCStyle.TELEPHONE_NUMBER);
        register(DMD_NAME, BCStyle.DMD_NAME);
        register(UID, BCStyle.UID);
        register(UNSTRUCTURED_NAME, BCStyle.UnstructuredName);
        register(UNSTRUCTURED_ADDRESS, BCStyle.UnstructuredAddress);
    }

    /**
     * Return the attribute type object identifier a registered value stands for, or
     * null if the value is not registered.
     */
    public static ASN1ObjectIdentifier getOID(int value)
    {
        return codeToOid.get(Integers.valueOf(value));
    }

    /**
     * Return the registered value for an attribute type object identifier, or null if
     * it is not registered.
     */
    public static Integer getValue(ASN1ObjectIdentifier oid)
    {
        return oidToCode.get(oid);
    }

    /**
     * Return true if the registered value is one whose attribute is always of type
     * IA5String (emailAddress, domainComponent), unambiguously represented using a
     * non-negative int per Section 3.1.4.
     */
    public static boolean isAlwaysIA5String(int value)
    {
        return value == EMAIL_ADDRESS || value == DOMAIN_COMPONENT;
    }

    private C509AttributeType()
    {
    }
}
