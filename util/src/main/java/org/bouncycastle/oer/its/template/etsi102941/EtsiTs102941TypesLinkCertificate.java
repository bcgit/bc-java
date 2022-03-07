package org.bouncycastle.oer.its.template.etsi102941;

import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.its.template.ieee1609dot2.IEEE1609dot2;
import org.bouncycastle.oer.its.template.ieee1609dot2.basetypes.Ieee1609Dot2BaseTypes;


public class EtsiTs102941TypesLinkCertificate
{
    /**
     * ToBeSignedLinkCertificate ::= SEQUENCE {
     * expiryTime          Time32,
     * certificateHash     HashedData,
     * ...
     * }
     */

    public static final OERDefinition.Builder ToBeSignedLinkCertificate = OERDefinition.seq(
        Ieee1609Dot2BaseTypes.Time32.label("expiryTime"),
        IEEE1609dot2.HashedData.label("certificateHash"),
        OERDefinition.extension()
    ).typeName("ToBeSignedLinkCertificate");


    /**
     * ToBeSignedLinkCertificateTlm ::= ToBeSignedLinkCertificate
     */
    public static final OERDefinition.Builder ToBeSignedLinkCertificateTlm = ToBeSignedLinkCertificate.typeName("ToBeSignedLinkCertificateTlm");

    /**
     * ToBeSignedLinkCertificateRca ::= ToBeSignedLinkCertificate
     */
    public static final OERDefinition.Builder ToBeSignedLinkCertificateRca = ToBeSignedLinkCertificate.typeName("ToBeSignedLinkCertificateRca");


}
