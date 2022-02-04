package org.bouncycastle.oer.its.template.etsi103097.extension;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.oer.Element;
import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.Switch;
import org.bouncycastle.oer.SwitchIndexer;
import org.bouncycastle.oer.its.template.ieee1609dot2.basetypes.Ieee1609Dot2BaseTypes;


/**
 * EtsiTs103097ExtensionModule
 * {itu-t(0) identified-organization(4) etsi(0) itsDomain(5) wg5(5) secHeaders(103097) extension(2) version1(1)}
 */

public class EtsiTs103097ExtensionModule
{

    public static final ASN1Integer etsiTs102941CrlRequestId = new ASN1Integer(1);
    public static final ASN1Integer etsiTs102941DeltaCtlRequestId = new ASN1Integer(2);


    /**
     * ExtId ::= INTEGER(0..255)
     */
    public static final OERDefinition.Builder ExtId = OERDefinition.integer(0, 255)
        .validSwitchValue(etsiTs102941CrlRequestId, etsiTs102941DeltaCtlRequestId)
        .label("ExtId");


    /**
     * EtsiTs102941CrlRequest::= SEQUENCE {
     * issuerId        HashedId8,
     * lastKnownUpdate Time32 OPTIONAL
     * }
     */
    public static final OERDefinition.Builder EtsiTs102941CrlRequest = OERDefinition.seq(
        Ieee1609Dot2BaseTypes.HashedId8.label("issuerId"),
        OERDefinition.optional(Ieee1609Dot2BaseTypes.Time32.label("lastKnownUpdate"))
    ).label("EtsiTs102941CrlRequest");


    /**
     * EtsiTs102941CtlRequest::= SEQUENCE {
     * issuerId             HashedId8,
     * lastKnownCtlSequence INTEGER (0..255) OPTIONAL
     * }
     */
    public static final OERDefinition.Builder EtsiTs102941CtlRequest = OERDefinition.seq(
        Ieee1609Dot2BaseTypes.HashedId8.label("issuerId"),
        OERDefinition.optional(OERDefinition.integer(0, 255).label("lastKnownCtlSequence"))
    ).label("EtsiTs102941CtlRequest");


    /**
     * EtsiTs102941DeltaCtlRequest::= EtsiTs102941CtlRequest
     */
    public static final OERDefinition.Builder EtsiTs102941DeltaCtlRequest = EtsiTs102941CtlRequest.label("EtsiTs102941DeltaCtlRequest");

    /**
     * Extension {EXT-TYPE : ExtensionTypes} ::= SEQUENCE {
     * id      EXT-TYPE.&extId({ExtensionTypes}),
     * content EXT-TYPE.&ExtContent({ExtensionTypes}{@.id})
     * }
     * <p>
     * This uses a switch to determine which OER definition to use based on the value of id.
     */
    public static final OERDefinition.Builder Extension = OERDefinition.seq(
        ExtId.labelPrefix("id"),
        OERDefinition.aSwitch(

            /**
             * Switch to examine "Extension.id" and select the correct oer definition.
             */
            new Switch()
            {
                private final Element etsiTs102941CrlRequestIdDef = EtsiTs102941CrlRequest.build();
                private final Element etsiTs102941DeltaCtlRequestIdDef = EtsiTs102941DeltaCtlRequest.build();


                public Element result(SwitchIndexer indexer)
                {
            /*
                etsiTs102941CrlRequestId      EtsiTs103097HeaderInfoExtensionId ::= 1 --'01'H
                etsiTs102941DeltaCtlRequestId EtsiTs103097HeaderInfoExtensionId ::= 2 --'02'H
             */


                    ASN1Integer type = ASN1Integer.getInstance(indexer.get(0));
                    if (type.equals(etsiTs102941CrlRequestId))
                    {
                        return etsiTs102941CrlRequestIdDef;
                    }
                    else if (type.equals(etsiTs102941DeltaCtlRequestId))
                    {
                        return etsiTs102941DeltaCtlRequestIdDef;
                    }

                    throw new IllegalStateException("unknown extension type " + type);

                }

            })).label("Extension");



    public static final OERDefinition.Builder EtsiOriginatingHeaderInfoExtension = Extension.label("EtsiOriginatingHeaderInfoExtension");

}
