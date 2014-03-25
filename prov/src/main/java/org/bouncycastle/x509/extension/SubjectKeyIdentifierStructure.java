package org.bouncycastle.x509.extension;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

/**
 * A high level subject key identifier.
 * @deprecated use JcaX509ExtensionUtils andSubjectKeyIdentifier.getInstance()
 */
public class SubjectKeyIdentifierStructure
    extends SubjectKeyIdentifier
{
    /**
     * Constructor which will take the byte[] returned from getExtensionValue()
     * 
     * @param encodedValue a DER octet encoded string with the extension structure in it.
     * @throws IOException on parsing errors.
     */
    public SubjectKeyIdentifierStructure(
        byte[]  encodedValue)
        throws IOException
    {
        super((ASN1OctetString)X509ExtensionUtil.fromExtensionValue(encodedValue));
    }
}
