package org.bouncycastle.oer.its.template.etsi102941;

import java.math.BigInteger;

import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.its.template.etsi102941.basetypes.EtsiTs102941BaseTypes;
import org.bouncycastle.oer.its.template.etsi103097.EtsiTs103097Module;

import static org.bouncycastle.oer.its.template.etsi103097.EtsiTs103097Module.EtsiTs103097Data_Signed;


public class EtsiTs102941TypesEnrolment
{
    /**
     * EnrolmentResponseCode ::= ENUMERATED {
     * ok(0),
     * cantparse, -- valid for any structure
     * badcontenttype, -- not encrypted, not signed, not enrolmentrequest
     * imnottherecipient, -- the "recipients" doesn't include me
     * unknownencryptionalgorithm, -- either kexalg or contentencryptionalgorithm
     * decryptionfailed, -- works for ECIES-HMAC and AES-CCM
     * unknownits, -- can't retrieve the ITS from the itsId
     * invalidsignature, -- signature verification of the request fails
     * invalidencryptionkey, -- signature is good, but the responseEncryptionKey is bad
     * baditsstatus, -- revoked, not yet active
     * incompleterequest, -- some elements are missing
     * deniedpermissions, -- requested permissions are not granted
     * invalidkeys, -- either the verification_key of the encryption_key is bad
     * deniedrequest, -- any other reason?
     * ... }
     */
    public static final OERDefinition.Builder EnrolmentResponseCode = OERDefinition.enumeration(
        OERDefinition.enumItem("ok", BigInteger.ZERO),
        "cantparse",
        "badcontenttype",
        "imnottherecipient",
        "unknownencryptionalgorithm",
        "decryptionfailed",
        "unknownits",
        "invalidsignature",
        "invalidencryptionkey",
        "baditsstatus",
        "incompleterequest",
        "deniedpermissions",
        "invalidkeys",
        "deniedrequest",
        OERDefinition.extension()
    ).typeName("EnrolmentResponseCode");


    /**
     * InnerEcResponse ::= SEQUENCE {
     * requestHash                           OCTET STRING (SIZE(16)),
     * responseCode                          EnrolmentResponseCode,
     * certificate                           EtsiTs103097Certificate OPTIONAL,
     * ...
     * }
     * (WITH COMPONENTS { responseCode (ok), certificate PRESENT }
     * | WITH COMPONENTS { responseCode (ALL EXCEPT ok), certificate ABSENT }
     * )
     */
    public static final OERDefinition.Builder InnerEcResponse = OERDefinition.seq(
        OERDefinition.octets(16).label("requestHash"),
        EnrolmentResponseCode.label("responseCode"),
        OERDefinition.optional(EtsiTs103097Module.EtsiTs103097Certificate.label("certificate")),
        OERDefinition.extension()
    ).typeName("InnerEcResponse");

    /**
     * InnerEcRequest ::= SEQUENCE {
     * itsId                                 OCTET STRING,
     * certificateFormat                     CertificateFormat,
     * publicKeys                            PublicKeys,
     * requestedSubjectAttributes            CertificateSubjectAttributes (WITH COMPONENTS{..., certIssuePermissions ABSENT}),
     * ...
     * }
     */
    public static final OERDefinition.Builder InnerEcRequest = OERDefinition.seq(
        OERDefinition.octets().label("itsId"),
        EtsiTs102941BaseTypes.CertificateFormat.label("certificateFormat"),
        EtsiTs102941BaseTypes.PublicKeys.label("publicKeys"),
        EtsiTs102941BaseTypes.CertificateSubjectAttributes.label("requestedSubjectAttributes"),
        OERDefinition.extension()
    ).typeName("InnerEcRequest");

    /**
     * InnerEcRequestSignedForPop::= EtsiTs103097Data-Signed{InnerEcRequest}
     */
    public static final OERDefinition.Builder InnerEcRequestSignedForPop =
        EtsiTs103097Data_Signed.typeName("InnerEcRequestSignedForPop");


}
