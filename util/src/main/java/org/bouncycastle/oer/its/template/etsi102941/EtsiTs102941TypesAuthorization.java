package org.bouncycastle.oer.its.template.etsi102941;

import java.math.BigInteger;

import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.its.template.etsi102941.basetypes.EtsiTs102941BaseTypes;
import org.bouncycastle.oer.its.template.etsi103097.EtsiTs103097Module;
import org.bouncycastle.oer.its.template.ieee1609dot2.basetypes.Ieee1609Dot2BaseTypes;


public class EtsiTs102941TypesAuthorization
{


    /**
     * ok(0),
     * -- ITS-&gt;AA
     * its-aa-cantparse, -- valid for any structure
     * its-aa-badcontenttype, -- not encrypted, not signed, not authorizationrequest
     * its-aa-imnottherecipient, -- the "recipients" of the outermost encrypted data doesn't include me
     * its-aa-unknownencryptionalgorithm, -- either kexalg or contentencryptionalgorithm
     * its-aa-decryptionfailed, -- works for ECIES-HMAC and AES-CCM
     * its-aa-keysdontmatch, -- HMAC keyTag verification fails
     * its-aa-incompleterequest, -- some elements are missing
     * its-aa-invalidencryptionkey, -- the responseEncryptionKey is bad
     * its-aa-outofsyncrequest, -- signingTime is outside acceptable limits
     * its-aa-unknownea, -- the EA identified by eaId is unknown to me
     * its-aa-invalidea, -- the EA certificate is revoked
     * its-aa-deniedpermissions, -- I, the AA, deny the requested permissions
     * -- AA-&gt;EA
     * aa-ea-cantreachea, -- the EA is unreachable (network error?)
     * -- EA-&gt;AA
     * ea-aa-cantparse, -- valid for any structure
     * ea-aa-badcontenttype, -- not encrypted, not signed, not authorizationrequest
     * ea-aa-imnottherecipient, -- the "recipients" of the outermost encrypted data doesn't include me
     * ea-aa-unknownencryptionalgorithm, -- either kexalg or contentencryptionalgorithm
     * ea-aa-decryptionfailed, -- works for ECIES-HMAC and AES-CCM
     * -- TODO: to be continued...
     * invalidaa, -- the AA certificate presented is invalid/revoked/whatever
     * invalidaasignature, -- the AA certificate presented can't validate the request signature
     * wrongea, -- the encrypted signature doesn't designate me as the EA
     * unknownits, -- can't retrieve the EC/ITS in my DB
     * invalidsignature, -- signature verification of the request by the EC fails
     * invalidencryptionkey, -- signature is good, but the key is bad
     * deniedpermissions, -- permissions not granted
     * deniedtoomanycerts, -- parallel limit
     */
    public static final OERDefinition.Builder AuthorizationResponseCode = OERDefinition.enumeration(
        OERDefinition.enumItem("ok", BigInteger.ZERO),
        "its-aa-cantparse",
        "its-aa-badcontenttype",
        "its-aa-imnottherecipient",
        "its-aa-unknownencryptionalgorithm",
        "its-aa-decryptionfailed",
        "its-aa-keysdontmatch",
        "its-aa-incompleterequest",
        "its-aa-invalidencryptionkey",
        "its-aa-outofsyncrequest",
        "its-aa-unknownea",
        "its-aa-invalidea",
        "its-aa-deniedpermissions",
        // -- AA->EA
        "aa-ea-cantreachea",
        // -- EA->AA
        "ea-aa-cantparse",
        "ea-aa-badcontenttype",
        "ea-aa-imnottherecipient",
        "ea-aa-unknownencryptionalgorithm",
        "ea-aa-decryptionfailed",
        // -- TODO: to be continued...
        "invalidaa",
        "invalidaasignature",
        "wrongea",
        "unknownits",
        "invalidsignature",
        "invalidencryptionkey",
        "deniedpermissions",
        "deniedtoomanycerts"
    ).typeName("AuthorizationResponseCode");


    /**
     * InnerAtResponse ::= SEQUENCE {
     * requestHash                   OCTET STRING (SIZE(16)),
     * responseCode                  AuthorizationResponseCode,
     * certificate                   EtsiTs103097Certificate OPTIONAL,
     * ...
     * }
     * (WITH COMPONENTS { responseCode (ok), certificate PRESENT }
     * | WITH COMPONENTS { responseCode (ALL EXCEPT ok), certificate ABSENT }
     * )
     */
    public static final OERDefinition.Builder InnerAtResponse = OERDefinition.seq(
        OERDefinition.octets(16).label("requestHash"),
        AuthorizationResponseCode.label("responseCode"),
        OERDefinition.optional(EtsiTs103097Module.EtsiTs103097Certificate.label("certificate")),
        OERDefinition.extension()
    ).typeName("InnerAtResponse");


    /**
     * SharedAtRequest ::= SEQUENCE {
     * eaId                          HashedId8,
     * keyTag                        OCTET STRING (SIZE(16)),
     * certificateFormat             CertificateFormat,
     * requestedSubjectAttributes    CertificateSubjectAttributes (WITH COMPONENTS{..., certIssuePermissions ABSENT}),
     * ...
     * }
     */
    public static final OERDefinition.Builder SharedAtRequest = OERDefinition.seq(
        Ieee1609Dot2BaseTypes.HashedId8.label("eaId"),
        OERDefinition.octets(16).label("keyTag"),
        EtsiTs102941BaseTypes.CertificateFormat.label("certificateFormat"),
        EtsiTs102941BaseTypes.CertificateSubjectAttributes.label("requestedSubjectAttributes"),
        OERDefinition.extension()

    ).typeName("SharedAtRequest");


    /**
     * InnerAtRequest ::= SEQUENCE {
     * publicKeys                    PublicKeys,
     * hmacKey                       OCTET STRING (SIZE(32)),
     * sharedAtRequest               SharedAtRequest,
     * ecSignature                   EcSignature,
     * ...
     * }
     */
    public static final OERDefinition.Builder InnerAtRequest = OERDefinition.seq(
        EtsiTs102941BaseTypes.PublicKeys.label("publicKeys"),
        OERDefinition.octets(32).label("hmacKey"),
        SharedAtRequest.label("sharedAtRequest"),
        EtsiTs102941BaseTypes.EcSignature.label("ecSignature")
    ).typeName("InnerAtRequest");



}
