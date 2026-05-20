package org.bouncycastle.pkcs;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.SecretBag;

/**
 * Builder for a {@link PKCS12SecretBag} carrying an arbitrary secret value
 * identified by the supplied bag-type OID.
 */
public class PKCS12SecretBagBuilder
{
    private final ASN1ObjectIdentifier secretTypeId;
    private final ASN1Encodable secretValue;

    public PKCS12SecretBagBuilder(ASN1ObjectIdentifier secretTypeId, ASN1Encodable secretValue)
    {
        this.secretTypeId = secretTypeId;
        this.secretValue = secretValue;
    }

    public PKCS12SecretBag build()
    {
        return new PKCS12SecretBag(new SecretBag(secretTypeId, secretValue));
    }
}
