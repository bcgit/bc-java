package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERTaggedObject;

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
public class EtsiTs102941DataContent
    extends ASN1Object
    implements ASN1Choice
{

    public static final int enrolmentRequest = 0;                      // InnerEcRequestSignedForPop,
    public static final int enrolmentResponse = 1;                    // InnerEcResponse,
    public static final int authorizationRequest = 2;                 // InnerAtRequest,
    public static final int authorizationResponse = 3;              // InnerAtResponse,
    public static final int certificateRevocationList = 4;           // ToBeSignedCrl,

    public static final int certificateTrustListTlm = 5;              // ToBeSignedTlmCtl,
    public static final int certificateTrustListRca = 6;             //  ToBeSignedRcaCtl,
    public static final int authorizationValidationRequest = 7;       //  AuthorizationValidationRequest,
    public static final int authorizationValidationResponse = 8;      //  AuthorizationValidationResponse,
    public static final int caCertificateRequest = 9;                 //  CaCertificateRequest,
    // Extension  ...,
    public static final int linkCertificateTlm = 10;                   // ToBeSignedLinkCertificateTlm,
    public static final int singleSignedLinkCertificateRca = 11;     //    ToBeSignedLinkCertificateRca,
    public static final int doubleSignedlinkCertificateRca = 12;     //    RcaSingleSignedLinkCertificateMessage


    private final int choice;
    private final ASN1Encodable etsiTs102941DataContent;

    public EtsiTs102941DataContent(int choice, ASN1Encodable etsiTs102941DataContent)
    {
        this.choice = choice;
        this.etsiTs102941DataContent = etsiTs102941DataContent;
    }


    private EtsiTs102941DataContent(ASN1TaggedObject asn1TaggedObject)
    {
        choice = asn1TaggedObject.getTagNo();
        switch (choice)
        {
        case enrolmentRequest:
            etsiTs102941DataContent = InnerEcRequestSignedForPop.getInstance(asn1TaggedObject.getExplicitBaseObject());
            return;
        case enrolmentResponse:
            etsiTs102941DataContent = InnerEcResponse.getInstance(asn1TaggedObject.getExplicitBaseObject());
            return;
        case authorizationRequest:
            etsiTs102941DataContent = InnerAtRequest.getInstance(asn1TaggedObject.getExplicitBaseObject());
            return;
        case authorizationResponse:
            etsiTs102941DataContent = InnerAtResponse.getInstance(asn1TaggedObject.getExplicitBaseObject());
            return;
        case certificateTrustListTlm:
            etsiTs102941DataContent = ToBeSignedTlmCtl.getInstance(asn1TaggedObject.getExplicitBaseObject());
            return;
        case certificateTrustListRca:
            etsiTs102941DataContent = ToBeSignedRcaCtl.getInstance(asn1TaggedObject.getExplicitBaseObject());
            return;
        case authorizationValidationRequest:
            etsiTs102941DataContent = AuthorizationValidationRequest.getInstance(asn1TaggedObject.getExplicitBaseObject());
            return;
        case authorizationValidationResponse:
            etsiTs102941DataContent = AuthorizationValidationResponse.getInstance(asn1TaggedObject.getExplicitBaseObject());
            return;
        case caCertificateRequest:
            etsiTs102941DataContent = CaCertificateRequest.getInstance(asn1TaggedObject.getExplicitBaseObject());
            return;
        //
        // This is incomplete
        //

        }

        throw new IllegalArgumentException("choice not implemented " + choice);

    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getEtsiTs102941DataContent()
    {
        return etsiTs102941DataContent;
    }

    public static EtsiTs102941DataContent getInstance(Object o)
    {
        if (o instanceof EtsiTs102941DataContent)
        {
            return (EtsiTs102941DataContent)o;
        }

        if (o != null)
        {
            return new EtsiTs102941DataContent(ASN1TaggedObject.getInstance(o, BERTags.CONTEXT_SPECIFIC));
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, etsiTs102941DataContent);
    }
}
