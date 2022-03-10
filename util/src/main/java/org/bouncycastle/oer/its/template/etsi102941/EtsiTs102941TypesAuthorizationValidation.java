package org.bouncycastle.oer.its.template.etsi102941;

import java.math.BigInteger;

import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.its.template.etsi102941.basetypes.EtsiTs102941BaseTypes;

import static org.bouncycastle.oer.its.template.etsi102941.EtsiTs102941TypesAuthorization.SharedAtRequest;

public class EtsiTs102941TypesAuthorizationValidation
{

    /**
     * AuthorizationValidationResponseCode ::= ENUMERATED {
     * ok(0),
     * cantparse, -- valid for any structure
     * badcontenttype, -- not encrypted, not signed, not permissionsverificationrequest
     * imnottherecipient, -- the "recipients" of the outermost encrypted data doesn't include me
     * unknownencryptionalgorithm, -- either kexalg or contentencryptionalgorithm
     * decryptionfailed, -- works for ECIES-HMAC and AES-CCM
     * invalidaa, -- the AA certificate presented is invalid/revoked/whatever
     * invalidaasignature, -- the AA certificate presented can't validate the request signature
     * wrongea, -- the encrypted signature doesn't designate me as the EA
     * unknownits, -- can't retrieve the EC/ITS in my DB
     * invalidsignature, -- signature verification of the request by the EC fails
     * invalidencryptionkey, -- signature is good, but the responseEncryptionKey is bad
     * deniedpermissions, -- requested permissions not granted
     * deniedtoomanycerts, -- parallel limit
     * deniedrequest, -- any other reason?
     * ... }
     */
    public static final OERDefinition.Builder AuthorizationValidationResponseCode = OERDefinition.enumeration(
        OERDefinition.enumItem("ok", BigInteger.ZERO),
        "cantparse", "badcontenttype",
        "imnottherecipient",
        "unknownencryptionalgorithm",
        "decryptionfailed",
        "invalidaa",
        "invalidaasignature",
        "wrongea",
        "unknownits",
        "invalidsignature",
        "invalidencryptionkey",
        "deniedpermissions",
        "deniedtoomanycerts",
        "deniedrequest"
    ).typeName("AuthorizationValidationResponseCode");

    /**
     * AuthorizationValidationRequest ::= SEQUENCE {
     * sharedAtRequest               SharedAtRequest,
     * ecSignature                   EcSignature,
     * ...
     * }
     */
    public static final OERDefinition.Builder AuthorizationValidationRequest = OERDefinition.seq(
        SharedAtRequest.label("sharedAtRequest"),
        EtsiTs102941BaseTypes.EcSignature.label("ecSignature"),
        OERDefinition.extension()
    ).typeName("AuthorizationValidationRequest");


    /**
     * AuthorizationValidationResponse ::= SEQUENCE {
     * requestHash                   OCTET STRING (SIZE(16)),
     * responseCode                  AuthorizationValidationResponseCode,
     * confirmedSubjectAttributes    CertificateSubjectAttributes (WITH COMPONENTS{..., certIssuePermissions ABSENT}) OPTIONAL,
     * ...
     * }
     * (WITH COMPONENTS { responseCode (ok), confirmedSubjectAttributes PRESENT }
     * | WITH COMPONENTS { responseCode (ALL EXCEPT ok), confirmedSubjectAttributes ABSENT }
     * )
     */
    public static final OERDefinition.Builder AuthorizationValidationResponse = OERDefinition.seq(
        OERDefinition.octets(16).label("requestHash"),
        AuthorizationValidationResponseCode.label("responseCode"),
        OERDefinition.optional(EtsiTs102941BaseTypes.CertificateSubjectAttributes.label("confirmedSubjectAttributes")),
        OERDefinition.extension()
    ).typeName("AuthorizationValidationResponse");

}

