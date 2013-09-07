package org.bouncycastle.asn1;

/**
 * Public facade of ASN.1 Boolean data.
 * <p>
 * Use following to place a new instance of ASN.1 Boolean in your dataset:
 * <p>
 * <ul>
 * <li> ASN1Boolean.TRUE literal
 * <li> ASN1Boolean.FALSE literal
 * <li> {@link DERBoolean#getInstance(boolean) ASN1Boolean.getInstance(boolean)}
 * <li> {@link DERBoolean#getInstance(int) ASN1Boolean.getInstance(int)}
 * </ul>
 */
public class ASN1Boolean
    extends DERBoolean
{
    /**
     * @deprecated Use {@link ASN1Boolean#getInstance(boolean) ASN1Boolean.getInstance(boolean)} instead.
     */
    public ASN1Boolean(boolean value)
    {
        super(value);
    }

    /**
     * Package local constructor.
     */
    ASN1Boolean(byte[] value)
    {
        super(value);
    }
}
