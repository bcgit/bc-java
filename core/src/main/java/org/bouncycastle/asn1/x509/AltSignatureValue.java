package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;

/**
 * X.509 Section 9.8.4.
 * <br/>
 * This extension may be used as a public-key certificate extension, a CRL extension or an AVL extension.
 * This alternative signature shall be created by the issuer using its alternative private key, and it shall be verified using the
 * alternative public key of the issuer.
 * <pre>
 * altSignatureValue EXTENSION ::= {
 *     SYNTAX AltSignatureValue
 *     IDENTIFIED BY id-ce-altSignatureValue }
 *
 * AltSignatureValue ::= BIT STRING
 * </pre>
 * This extension can only be created by a signer holding a multiple cryptographic algorithms public-key certificate. When
 * creating the alternative digital signature on an issued public-key certificate or CRL, the signer shall use its alternative
 * private key.
 * <br/>
 * The procedures for creating and validating alternative digital signatures are specified in:
 * <ul>
 * <li>clause 7.2.2 for public-key certificates;</li>
 * <li>clause 7.10.3 for CRLs: and</li>
 * <li>clause 11.4 for AVLs.</li>
 * </ul>
 */
public class AltSignatureValue
    extends ASN1Object
{
    private final ASN1BitString signature;

    public static AltSignatureValue getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1BitString.getInstance(obj, explicit));
    }

    public static AltSignatureValue getInstance(
        Object obj)
    {
        if (obj instanceof AltSignatureValue)
        {
            return (AltSignatureValue)obj;
        }
        else if (obj != null)
        {
            return new AltSignatureValue(ASN1BitString.getInstance(obj));
        }

        return null;
    }

    public static AltSignatureValue fromExtensions(Extensions extensions)
    {
        return getInstance(Extensions.getExtensionParsedValue(extensions, Extension.altSignatureValue));
    }

    private AltSignatureValue(ASN1BitString signature)
    {
        this.signature = signature;
    }

    /**
     * Base constructor.
     *
     * @param signature  a signature value, based on the enclosing certificate.
     */
    public AltSignatureValue(byte[] signature)
    {
        this.signature = new DERBitString(signature);
    }

    /**
     * Return the alternate signature to verify the certificate.
     *
     * @return certificate's alternate signature.
     */
    public ASN1BitString getSignature()
    {
        return signature;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return signature;
    }
}
