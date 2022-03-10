package org.bouncycastle.oer.its.template.etsi102941;

import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.its.template.etsi102941.basetypes.EtsiTs102941BaseTypes;
import org.bouncycastle.oer.its.template.etsi103097.EtsiTs103097Module;


public class EtsiTs102941MessagesCa
{


    /**
     * EnrolmentRequestMessage ::= EtsiTs103097Data-SignedAndEncrypted-Unicast {EtsiTs102941Data (WITH COMPONENTS{..., content (WITH COMPONENTS{enrolmentRequest PRESENT})})}
     */
    public static final OERDefinition.Builder EnrolmentRequestMessage =
        EtsiTs103097Module.EtsiTs103097Data_SignedAndEncrypted_Unicast.typeName("EnrolmentRequestMessage");

    /**
     * EnrolmentResponseMessage ::= EtsiTs103097Data-SignedAndEncrypted-Unicast {EtsiTs102941Data (WITH COMPONENTS{..., content (WITH COMPONENTS{enrolmentResponse PRESENT})})}
     */
    public static final OERDefinition.Builder EnrolmentResponseMessage =
        EtsiTs103097Module.EtsiTs103097Data_SignedAndEncrypted_Unicast.typeName("EnrolmentResponseMessage");


    /**
     * AuthorizationRequestMessage ::= EtsiTs103097Data-Encrypted-Unicast {EtsiTs102941Data (WITH COMPONENTS{..., content (WITH COMPONENTS{authorizationRequest PRESENT})})}
     */

    public static final OERDefinition.Builder AuthorizationRequestMessage =
        EtsiTs103097Module.EtsiTs103097Data_Encrypted_Unicast.typeName("AuthorizationRequestMessage");

    /**
     * AuthorizationRequestMessageWithPop ::= EtsiTs103097Data-SignedAndEncrypted-Unicast {EtsiTs102941Data (WITH COMPONENTS{..., content (WITH COMPONENTS{authorizationRequest PRESENT})})}
     */

    public static final OERDefinition.Builder AuthorizationRequestMessageWithPop =
        EtsiTs103097Module.EtsiTs103097Data_SignedAndEncrypted_Unicast.typeName("AuthorizationRequestMessageWithPop");


    /**
     * AuthorizationResponseMessage ::= EtsiTs103097Data-SignedAndEncrypted-Unicast {EtsiTs102941Data (WITH COMPONENTS{..., content (WITH COMPONENTS{authorizationResponse PRESENT})})}
     */

    public static final OERDefinition.Builder AuthorizationResponseMessage =
        EtsiTs103097Module.EtsiTs103097Data_SignedAndEncrypted_Unicast.typeName("AuthorizationResponseMessage");


    /**
     * CertificateRevocationListMessage ::= EtsiTs103097Data-Signed{EtsiTs102941Data (WITH COMPONENTS{..., content (WITH COMPONENTS{certificateRevocationList PRESENT})})}
     */
    public static final OERDefinition.Builder CertificateRevocationListMessage =
        EtsiTs103097Module.EtsiTs103097Data_Signed.typeName("CertificateRevocationListMessage");


    /**
     * TlmCertificateTrustListMessage ::= EtsiTs103097Data-Signed{EtsiTs102941Data (WITH COMPONENTS{..., content (WITH COMPONENTS{certificateTrustListTlm PRESENT})})}
     */

    public static final OERDefinition.Builder TlmCertificateTrustListMessage =
        EtsiTs103097Module.EtsiTs103097Data_Signed.typeName("TlmCertificateTrustListMessage");


    /**
     * RcaCertificateTrustListMessage ::= EtsiTs103097Data-Signed{EtsiTs102941Data (WITH COMPONENTS{..., content (WITH COMPONENTS{certificateTrustListRca PRESENT})})}
     */

    public static final OERDefinition.Builder RcaCertificateTrustListMessage =
        EtsiTs103097Module.EtsiTs103097Data_Signed.typeName("RcaCertificateTrustListMessage");


    /**
     * RcaSingleSignedLinkCertificateMessage ::= EtsiTs103097Data-Signed {EtsiTs102941Data (WITH COMPONENTS{..., content (WITH COMPONENTS{singleSignedLinkCertificateRca PRESENT})})}
     */
    public static final OERDefinition.Builder RcaSingleSignedLinkCertificateMessage = EtsiTs103097Module.EtsiTs103097Data_Signed.typeName("RcaSingleSignedLinkCertificateMessage");


    /**
     * EtsiTs102941DataContent ::= CHOICE {
     * enrolmentRequest                        InnerEcRequestSignedForPop,
     * enrolmentResponse                       InnerEcResponse,
     * authorizationRequest                    InnerAtRequest,
     * authorizationResponse                   InnerAtResponse,
     * certificateRevocationList               ToBeSignedCrl,
     * <p>
     * certificateTrustListTlm                 ToBeSignedTlmCtl,
     * certificateTrustListRca                 ToBeSignedRcaCtl,
     * authorizationValidationRequest          AuthorizationValidationRequest,
     * authorizationValidationResponse         AuthorizationValidationResponse,
     * caCertificateRequest                    CaCertificateRequest,
     * ...,
     * linkCertificateTlm                      ToBeSignedLinkCertificateTlm,
     * singleSignedLinkCertificateRca          ToBeSignedLinkCertificateRca,
     * doubleSignedlinkCertificateRca          RcaSingleSignedLinkCertificateMessage
     * }
     */

    public static final OERDefinition.Builder EtsiTs102941DataContent = OERDefinition.choice(
        EtsiTs102941TypesEnrolment.InnerEcRequestSignedForPop.label("enrolmentRequest"),
        EtsiTs102941TypesEnrolment.InnerEcResponse.label("enrolmentResponse"),
        EtsiTs102941TypesAuthorization.InnerAtRequest.label("authorizationRequest"),
        EtsiTs102941TypesAuthorization.InnerAtResponse.label("authorizationResponse"),
        EtsiTs102941TrustLists.ToBeSignedCrl.label("certificateRevocationList"),
        EtsiTs102941TrustLists.ToBeSignedTlmCtl.label("certificateTrustListTlm"),
        EtsiTs102941TrustLists.ToBeSignedRcaCtl.label("certificateTrustListRca"),
        EtsiTs102941TypesAuthorizationValidation.AuthorizationValidationRequest.label("authorizationValidationRequest"),
        EtsiTs102941TypesAuthorizationValidation.AuthorizationValidationResponse.label("authorizationValidationResponse"),
        EtsiTs102941TypesCaManagement.CaCertificateRequest.label("caCertificateRequest"),
        OERDefinition.extension(
            EtsiTs102941TypesLinkCertificate.ToBeSignedLinkCertificateTlm.label("linkCertificateTlm"),
            EtsiTs102941TypesLinkCertificate.ToBeSignedLinkCertificateRca.label("singleSignedLinkCertificateRca"),
            RcaSingleSignedLinkCertificateMessage.label("doubleSignedlinkCertificateRca"))
    ).typeName("EtsiTs102941DataContent");

    /**
     * EtsiTs102941Data::= SEQUENCE {
     * version Version (v1),
     * content EtsiTs102941DataContent
     * }
     */
    public static final OERDefinition.Builder EtsiTs102941Data = OERDefinition.seq(
        EtsiTs102941BaseTypes.Version.label("version"),
        EtsiTs102941DataContent.label("content")
    ).typeName("EtsiTs102941Data");


    /**
     * AuthorizationValidationRequestMessage ::= EtsiTs103097Data-SignedAndEncrypted-Unicast {EtsiTs102941Data (WITH COMPONENTS{..., content (WITH COMPONENTS{authorizationValidationRequest PRESENT})})}
     */
    public static final OERDefinition.Builder AuthorizationValidationRequestMessage =
        EtsiTs103097Module.EtsiTs103097Data_SignedAndEncrypted_Unicast.typeName("AuthorizationValidationRequestMessage");


    /**
     * CaCertificateRequestMessage ::= EtsiTs103097Data-Signed {EtsiTs102941Data(WITH COMPONENTS{..., content (WITH COMPONENTS{caCertificateRequest PRESENT})})}
     */
    public static final OERDefinition.Builder CaCertificateRequestMessage =
        EtsiTs103097Module.EtsiTs103097Data_Signed.typeName("CaCertificateRequestMessage");


    /**
     * CaCertificateRekeyingMessage ::= EtsiTs103097Data-Signed {EtsiTs103097Data-Signed {EtsiTs102941Data(WITH COMPONENTS{..., content (WITH COMPONENTS{caCertificateRequest PRESENT})})}}
     */
    public static final OERDefinition.Builder CaCertificateRekeyingMessage =
        EtsiTs103097Module.EtsiTs103097Data_Signed.typeName("CaCertificateRekeyingMessage");

    /**
     * TlmLinkCertificateMessage ::= EtsiTs103097Data-Signed {EtsiTs102941Data (WITH COMPONENTS{..., content (WITH COMPONENTS{linkCertificateTlm PRESENT})})}
     */
    public static final OERDefinition.Builder TlmLinkCertificateMessage =
        EtsiTs103097Module.EtsiTs103097Data_Signed.typeName("TlmLinkCertificateMessage");


    /**
     * RcaDoubleSignedLinkCertificateMessage ::= EtsiTs103097Data-Signed {EtsiTs102941Data (WITH COMPONENTS{..., content (WITH COMPONENTS{doubleSignedlinkCertificateRca PRESENT})})}
     */
    public static final OERDefinition.Builder RcaDoubleSignedLinkCertificateMessage =
        EtsiTs103097Module.EtsiTs103097Data_Signed.typeName("RcaDoubleSignedLinkCertificateMessage");


}
