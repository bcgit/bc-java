package org.bouncycastle.oer.its.template.etsi102941;

import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.its.template.etsi102941.basetypes.EtsiTs102941BaseTypes;
import org.bouncycastle.oer.its.template.ieee1609dot2.basetypes.Ieee1609Dot2BaseTypes;

import static org.bouncycastle.oer.its.template.etsi103097.EtsiTs103097Module.EtsiTs103097Certificate;
import static org.bouncycastle.oer.its.template.ieee1609dot2.basetypes.Ieee1609Dot2BaseTypes.HashedId8;

public class EtsiTs102941TrustLists
{

    public static final OERDefinition.Builder CrlEntry = HashedId8.typeName("CrlEntry");


    /**
     * SEQUENCE OF CrlEntry,
     */
    public static final OERDefinition.Builder SequenceOfCrlEntry =
        OERDefinition.seqof(CrlEntry).typeName("SequenceOfCrlEntry");





    /**
     * ToBeSignedCrl ::= SEQUENCE {
     * version    Version,
     * thisUpdate Time32,
     * nextUpdate Time32,
     * entries SEQUENCE OF CrlEntry,
     * ...
     * }
     */
    public static final OERDefinition.Builder ToBeSignedCrl = OERDefinition.seq(
        EtsiTs102941BaseTypes.Version.label("version"),
        Ieee1609Dot2BaseTypes.Time32.label("thisUpdate"),
        Ieee1609Dot2BaseTypes.Time32.label("nextUpdate"),
        SequenceOfCrlEntry.label("entries"),
        OERDefinition.extension()
    ).typeName("ToBeSignedCrl");


    /**
     * Url::= IA5String
     */
    public static final OERDefinition.Builder Url = OERDefinition.ia5String().typeName("Url");

    /**
     * DcDelete ::= Url
     */
    public static final OERDefinition.Builder DcDelete = Url.typeName("DcDelete");


    /**
     * DcEntry ::= SEQUENCE {
     * url   Url,
     * cert  SEQUENCE OF HashedId8
     * }
     */
    public static final OERDefinition.Builder DcEntry = OERDefinition.seq(
        Url.label("url"),
        Ieee1609Dot2BaseTypes.SequenceOfHashedId8.label("cert")
    ).typeName("DcEntry");

    /**
     * AaEntry ::= SEQUENCE {
     * aaCertificate EtsiTs103097Certificate,
     * accessPoint Url
     * }
     */
    public static final OERDefinition.Builder AaEntry = OERDefinition.seq(
        EtsiTs103097Certificate.label("aaCertificate"),
        Url.label("accessPoint")
    ).typeName("AaEntry");


    /**
     * EaEntry ::= SEQUENCE {
     * eaCertificate     EtsiTs103097Certificate,
     * aaAccessPoint     Url,
     * itsAccessPoint    Url OPTIONAL
     * }
     */
    public static final OERDefinition.Builder EaEntry = OERDefinition.seq(
        EtsiTs103097Certificate.label("eaCertificate"),
        Url.label("aaAccessPoint"),
        OERDefinition.optional(Url.label("itsAccessPoint"))
    ).typeName("EaEntry");


    /**
     * RootCaEntry ::= SEQUENCE {
     * selfsignedRootCa EtsiTs103097Certificate,
     * successorTo      EtsiTs103097Certificate OPTIONAL
     * }
     */
    public static final OERDefinition.Builder RootCaEntry = OERDefinition.seq(
        EtsiTs103097Certificate.label("selfsignedRootCa"),
        OERDefinition.optional(EtsiTs103097Certificate.label("successorTo"))
    ).typeName("RootCaEntry");

    /**
     * TlmEntry::= SEQUENCE {
     * selfSignedTLMCertificate EtsiTs103097Certificate,
     * successorTo              EtsiTs103097Certificate OPTIONAL,
     * accessPoint              Url
     * }
     */

    public static final OERDefinition.Builder TlmEntry = OERDefinition.seq(
        EtsiTs103097Certificate.label("selfSignedTLMCertificate"),
        OERDefinition.optional(EtsiTs103097Certificate.label("successorTo")),
        Url.label("accessPoint")
    ).typeName("TlmEntry");


    /**
     * CtlDelete ::= CHOICE {
     * cert  HashedId8,
     * dc    DcDelete,
     * ...
     * }
     */
    public static final OERDefinition.Builder CtlDelete = OERDefinition.choice(
        HashedId8.label("cert"),
        DcDelete.label("dc"),
        OERDefinition.extension()
    ).typeName("CtlDelete");


    /**
     * CtlEntry ::= CHOICE {
     * rca   RootCaEntry,
     * ea    EaEntry,
     * aa    AaEntry,
     * dc    DcEntry,
     * tlm   TlmEntry,
     * ...
     * }
     */

    public static final OERDefinition.Builder CtlEntry = OERDefinition.choice(
        RootCaEntry.label("rca"),
        EaEntry.label("ea"),
        AaEntry.label("aa"),
        DcEntry.label("dc"),
        TlmEntry.label("tlm"),
        OERDefinition.extension()
    ).typeName("CtlEntry");

    /**
     * CtlCommand ::= CHOICE {
     * add CtlEntry,
     * delete  CtlDelete,
     * ...
     * }
     */
    public static final OERDefinition.Builder CtlCommand = OERDefinition.choice(
        CtlEntry.label("add"),
        CtlDelete.label("delete"),
        OERDefinition.extension()
    ).typeName("CtlCommand");

    /**
     * SEQUENCE OF CtlCommand
     */
    public static final OERDefinition.Builder SequenceOfCtlCommand = OERDefinition.seqof(CtlCommand).typeName("SequenceOfCtlCommand");


    /**
     * CtlFormat ::= SEQUENCE {
     * version     Version,
     * nextUpdate  Time32,
     * isFullCtl   BOOLEAN,
     * ctlSequence INTEGER (0..255),
     * ctlCommands SEQUENCE OF CtlCommand,
     * ...
     * }
     */

    public static final OERDefinition.Builder CtlFormat = OERDefinition.seq(
        EtsiTs102941BaseTypes.Version.label("version"),
        Ieee1609Dot2BaseTypes.Time32.label("nextUpdate"),
        OERDefinition.bool().label("isFullCtl"),
        OERDefinition.integer(0, 255).label("ctlSequence"),
        SequenceOfCtlCommand.label("ctlCommands"),
        OERDefinition.extension()
    ).typeName("CtlFormat");

    /**
     * DeltaCtl::= CtlFormat (WITH COMPONENTS {...,
     * isFullCtl(FALSE)
     * })
     */
    public static final OERDefinition.Builder DeltaCtl = CtlFormat.typeName("DeltaCtl");


    /**
     * FullCtl::= CtlFormat ( WITH COMPONENTS {...,
     * isFullCtl ( TRUE ),
     * ctlCommands ( WITH COMPONENT(
     * ( WITH COMPONENTS {...,
     * delete ABSENT
     * })
     * ))
     * })
     */
    public static final OERDefinition.Builder FullCtl = CtlFormat.typeName("FullCtl");


    /**
     * ToBeSignedTlmCtl ::= CtlFormat (FullCtl | DeltaCtl) (WITH COMPONENTS {...,
     *   ctlCommands ( WITH COMPONENT(
     *     ( WITH COMPONENTS {...,
     *       add ( WITH COMPONENTS {...,
     *         ea ABSENT,
     *         aa ABSENT
     *       })
     *     })
     *   ))
     * })
     */

    public static final OERDefinition.Builder ToBeSignedTlmCtl = CtlFormat.typeName("ToBeSignedRcaCtl");


    /**
     * ToBeSignedRcaCtl ::= CtlFormat (FullCtl | DeltaCtl) ( WITH COMPONENTS {...,
     * ctlCommands ( WITH COMPONENT(
     * ( WITH COMPONENTS {...,
     * add ( WITH COMPONENTS {...,
     * rca ABSENT,
     * tlm ABSENT
     * })
     * })
     * ))
     * })
     */
    public static final OERDefinition.Builder ToBeSignedRcaCtl = CtlFormat.typeName("ToBeSignedRcaCtl");


}
