package org.bouncycastle.cbor.c509;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.util.Arrays;

/**
 * A single C509 certification request attribute (Section 4.3 of
 * draft-ietf-cose-cbor-encoded-cert-20):
 * <pre>
 * CRAttribute = ( ( attributeType: int, attributeValue: Defined ) //
 *                 ( attributeType: ~oid, attributeValue: bytes ) )
 * </pre>
 * The C509 CR Attributes Registry (Section 8.7) defines values 0 (extensionRequest),
 * 1 (challengePassword) and 2 (privateKeyPossessionStatement). For the generic ~oid
 * form the value byte string carries the DER encoding of the single attribute value.
 */
public class C509Attribute
{
    /** Extension Request (1.2.840.113549.1.9.14), RFC 2985. */
    public static final int EXTENSION_REQUEST = 0;
    /** Challenge Password (1.2.840.113549.1.9.7), RFC 2985. */
    public static final int CHALLENGE_PASSWORD = 1;
    /** Private Key Possession Statement (1.3.6.1.4.1.22112.2.1), RFC 9883. */
    public static final int PRIVATE_KEY_POSSESSION_STATEMENT = 2;

    private final Integer registryValue;
    private final ASN1ObjectIdentifier oid;
    private final byte[] cborValue;

    C509Attribute(Integer registryValue, ASN1ObjectIdentifier oid, byte[] cborValue)
    {
        this.registryValue = registryValue;
        this.oid = oid;
        this.cborValue = cborValue;
    }

    /**
     * Return the C509 CR Attributes Registry value when this attribute is carried in
     * the int-coded form, or null when it uses the generic ~oid form.
     */
    public Integer getRegistryValue()
    {
        return registryValue;
    }

    /**
     * Return the attribute's object identifier - resolved from the registry for the
     * int-coded form.
     */
    public ASN1ObjectIdentifier getAttrType()
    {
        return oid;
    }

    /**
     * Return the CBOR encoding of the attribute value item.
     */
    public byte[] getValueEncoding()
    {
        return Arrays.clone(cborValue);
    }
}
