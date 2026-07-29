package org.bouncycastle.cbor.c509;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.util.Arrays;

/**
 * A single C509 extension (Section 3.1.10 of draft-ietf-cose-cbor-encoded-cert-20):
 * <pre>
 * Extension = ( ( extensionID: int, extensionValue: Defined ) //
 *               ( extensionID: ~oid, extensionValue: bytes / [ bytes ] ) )
 * </pre>
 * For the int-coded form the absolute value of the int is the C509 Extensions
 * Registry value, the sign carries criticality (negative for critical), and the value
 * is the specific CBOR encoding of Section 3.3. For the generic form the value is the
 * extnValue OCTET STRING value field, wrapped in a single element array when the
 * extension is critical.
 * <p>
 * Both forms materialize the DER encoding of the extension value at construction, so
 * an instance always answers {@link #getExtnId()} and {@link #getExtnValue()}
 * regardless of the wire form used.
 */
public class C509Extension
{
    private final Integer registryValue;
    private final ASN1ObjectIdentifier oid;
    private final boolean critical;
    private final byte[] cborValue;
    private final byte[] extnValue;

    C509Extension(Integer registryValue, ASN1ObjectIdentifier oid, boolean critical, byte[] cborValue,
        byte[] extnValue)
    {
        this.registryValue = registryValue;
        this.oid = oid;
        this.critical = critical;
        this.cborValue = cborValue;
        this.extnValue = extnValue;
    }

    /**
     * Return the C509 Extensions Registry value when this extension is carried in the
     * int-coded form, or null when it uses the generic ~oid form.
     */
    public Integer getRegistryValue()
    {
        return registryValue;
    }

    /**
     * Return true if the extension is critical.
     */
    public boolean isCritical()
    {
        return critical;
    }

    /**
     * Return the extension's object identifier - resolved from the registry for the
     * int-coded form.
     */
    public ASN1ObjectIdentifier getExtnId()
    {
        return oid;
    }

    /**
     * Return the DER encoding of the extension value (the extnValue OCTET STRING
     * value field).
     */
    public byte[] getExtnValue()
    {
        return Arrays.clone(extnValue);
    }

    /**
     * Return the CBOR item carrying the extension value in the int-coded form, or
     * null for the generic form.
     */
    byte[] getCborValue()
    {
        return cborValue;
    }
}
