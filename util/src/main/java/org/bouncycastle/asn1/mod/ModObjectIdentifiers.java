package org.bouncycastle.asn1.mod;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface ModObjectIdentifiers
{
    //TODO: add more from RFC 6268, RFC 5911

    //   id_mod OBJECT IDENTIFIER  ::= { iso(1) identified_organization(3)
    //       dod(6) internet(1) security(5) mechanisms(5) pkix(7) mod(0) }
    ASN1ObjectIdentifier id_mod = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.0");

    /**
     * PUBLIC-KEY, SIGNATURE-ALGORITHM, SMIME-CAPS
     *      FROM AlgorithmInformation-2009  -- RFC 5911 [CMSASN1]
     *      { iso(1) identified-organization(3) dod(6) internet(1)
     *      security(5) mechanisms(5) pkix(7) id-mod(0)
     *      id-mod-algorithmInformation-02(58) } ;
     *      1.3.6.1.5.5.7.0.58
     */
    ASN1ObjectIdentifier id_mod_algorithmInformation_02 = id_mod.branch("58");
}
