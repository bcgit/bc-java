package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

public interface CMSObjectIdentifiers
{
    static final ASN1ObjectIdentifier    data = PKCSObjectIdentifiers.data;
    static final ASN1ObjectIdentifier    signedData = PKCSObjectIdentifiers.signedData;
    static final ASN1ObjectIdentifier    envelopedData = PKCSObjectIdentifiers.envelopedData;
    static final ASN1ObjectIdentifier    signedAndEnvelopedData = PKCSObjectIdentifiers.signedAndEnvelopedData;
    static final ASN1ObjectIdentifier    digestedData = PKCSObjectIdentifiers.digestedData;
    static final ASN1ObjectIdentifier    encryptedData = PKCSObjectIdentifiers.encryptedData;
    static final ASN1ObjectIdentifier    authenticatedData = PKCSObjectIdentifiers.id_ct_authData;
    static final ASN1ObjectIdentifier    compressedData = PKCSObjectIdentifiers.id_ct_compressedData;
    static final ASN1ObjectIdentifier    authEnvelopedData = PKCSObjectIdentifiers.id_ct_authEnvelopedData;
    static final ASN1ObjectIdentifier    timestampedData = PKCSObjectIdentifiers.id_ct_timestampedData;

    /**
     * The other Revocation Info arc
     * id-ri OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
     *                                   dod(6) internet(1) security(5) mechanisms(5) pkix(7) ri(16) }
     */
    static final ASN1ObjectIdentifier    id_ri = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.16");

    static final ASN1ObjectIdentifier    id_ri_ocsp_response = id_ri.branch("2");
    static final ASN1ObjectIdentifier    id_ri_scvp = id_ri.branch("4");
}
