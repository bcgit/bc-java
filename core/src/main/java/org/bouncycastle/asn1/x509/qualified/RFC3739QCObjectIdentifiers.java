package org.bouncycastle.asn1.x509.qualified;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

public interface RFC3739QCObjectIdentifiers
{
    /** OID: 1.3.6.1.5.5.7.11 */
    ASN1ObjectIdentifier id_qcs = X509ObjectIdentifiers.id_pkix.branch("11");
    /** OID: 1.3.6.1.5.5.7.11.1 */
    ASN1ObjectIdentifier id_qcs_pkixQCSyntax_v1 = id_qcs.branch("1");
    /** OID: 1.3.6.1.5.5.7.11.2 */
    ASN1ObjectIdentifier id_qcs_pkixQCSyntax_v2 = id_qcs.branch("2");
}
