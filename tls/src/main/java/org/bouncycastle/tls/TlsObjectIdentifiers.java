package org.bouncycastle.tls;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

/**
 * Object Identifiers associated with TLS extensions.
 */
public interface TlsObjectIdentifiers
{
    /**
     * RFC 7633
     */
    static final ASN1ObjectIdentifier id_pe_tlsfeature = X509ObjectIdentifiers.id_pe.branch("24");
}
