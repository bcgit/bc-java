package org.bouncycastle.oer.its.template;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.Switch;
import org.bouncycastle.oer.SwitchIndexer;
import org.bouncycastle.util.BigIntegers;


public class EtsiTs103097ExtensionModule
{
    /**
     * ExtId ::= INTEGER(0..255)
     */
    public static final OERDefinition.Builder ExtId = OERDefinition.integer(0, 255).label("ExtId");


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
    public static final OERDefinition.Builder Extension = OERDefinition.seq(ExtId.labelPrefix("id"),
        OERDefinition.aSwitch(

            /**
             * Switch to examine "Extension.id" and select the correct oer definition.
             */
            new Switch()
            {
                private final OERDefinition.Element etsiTs102941CrlRequestId = EtsiTs102941CrlRequest.build();
                private final OERDefinition.Element etsiTs102941DeltaCtlRequestId = EtsiTs102941DeltaCtlRequest.build();

                @Override
                public OERDefinition.Element result(SwitchIndexer indexer)
                {
            /*
                etsiTs102941CrlRequestId      EtsiTs103097HeaderInfoExtensionId ::= 1 --'01'H
                etsiTs102941DeltaCtlRequestId EtsiTs103097HeaderInfoExtensionId ::= 2 --'02'H
             */

                    int type = BigIntegers.intValueExact(ASN1Integer.getInstance(indexer.get(0)).getValue());

                    switch (type)
                    {
                    case 1:
                        return etsiTs102941CrlRequestId;
                    case 2:
                        return etsiTs102941DeltaCtlRequestId;
                    default:
                        throw new IllegalStateException("unknown extension type " + type);
                    }
                }
            })).label("Extension");


}
