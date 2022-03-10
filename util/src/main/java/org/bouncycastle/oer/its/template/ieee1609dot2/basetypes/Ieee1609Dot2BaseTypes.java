package org.bouncycastle.oer.its.template.ieee1609dot2.basetypes;


import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.oer.OERDefinition;

public class Ieee1609Dot2BaseTypes
{
    /**
     * Uint3  ::= INTEGER (0..7)
     */
    public static final OERDefinition.Builder UINT3 = OERDefinition.integer(0, 7).typeName("UINT3");

    /**
     * Uint8  ::= INTEGER (0..255)
     */
    public static final OERDefinition.Builder UINT8 = OERDefinition.integer(0, 255).typeName("UINT8");

    /**
     * Uint16 ::= INTEGER (0..65535)
     */
    public static final OERDefinition.Builder UINT16 = OERDefinition.integer(0, 65535).typeName("UINT16");

    /**
     * Uint32 ::= INTEGER (0..4294967295)
     */
    public static final OERDefinition.Builder UINT32 = OERDefinition.integer(0, 4294967295L).typeName("UINT32");

    /**
     * Uint64 ::= INTEGER (0..18446744073709551615)
     */
    public static final OERDefinition.Builder UINT64 = OERDefinition.integer(BigInteger.ZERO,
        new BigInteger("18446744073709551615")).typeName("UINT64");

    /**
     * SequenceOfUint16 ::= SEQUENCE OF Uint16
     */
    public static final OERDefinition.Builder SequenceOfUint16 = OERDefinition.seqof(UINT16).typeName("SequenceOfUint16");

    /**
     * SequenceOfUint8  ::= SEQUENCE OF Uint8
     */
    public static final OERDefinition.Builder SequenceOfUint8 =
        OERDefinition.seqof(UINT8).typeName("SequenceOfUint8");

    //
    // Octet string types
    //
    public static final OERDefinition.Builder HashedId3 = OERDefinition.octets(3).typeName("HashedId3");
    public static final OERDefinition.Builder HashedId8 = OERDefinition.octets(8).typeName("HashedId8");
    public static final OERDefinition.Builder HashedId10 = OERDefinition.octets(10).typeName("HashedId10");
    public static final OERDefinition.Builder HashedId32 = OERDefinition.octets(32).typeName("HashedId32");


    public static final OERDefinition.Builder SequenceOfHashedId3 = OERDefinition.seqof(HashedId3).typeName("SequenceOfHashedId3");

    // Not actually in this module but redeclared elsewhere inline, this is here to standardize this type.
    public static final OERDefinition.Builder SequenceOfHashedId8 = OERDefinition.seqof(HashedId8).typeName("SequenceOfHashedId8");





    //
    // Time.
    //
    public static final OERDefinition.Builder Time32 = UINT32.typeName("Time32");
    public static final OERDefinition.Builder Time64 = UINT64.typeName("Time64");

    /**
     * Duration ::= CHOICE {
     * microseconds  Uint16,
     * milliseconds  Uint16,
     * seconds       Uint16,
     * minutes       Uint16,
     * hours         Uint16,
     * sixtyHours    Uint16,
     * years         Uint16
     * }
     */
    public static final OERDefinition.Builder Duration = OERDefinition.choice(
        UINT16.label("microseconds"),
        UINT16.label("milliseconds"),
        UINT16.label("seconds"),
        UINT16.label("minutes"),
        UINT16.label("hours"),
        UINT16.label("sixtyHours"),
        UINT16.label("years")
    ).typeName("Duration");


    /**
     * ValidityPeriod ::= SEQUENCE {
     * start     Time32,
     * duration  Duration
     * }
     */
    public static final OERDefinition.Builder ValidityPeriod =
        OERDefinition.seq(
            Time32.label("start"),
            Duration.label("duration")
        ).typeName("ValidityPeriod");

    //
    // Pseudonym Linkage
    //

    /**
     * IValue ::= Uint16
     */
    public static final OERDefinition.Builder IValue = UINT16.copy().typeName("IValue");

    /**
     * Hostname ::= UTF8String (SIZE(0..255))
     */
    public static final OERDefinition.Builder Hostname = OERDefinition.utf8String(0, 255).typeName("Hostname");

    /**
     * LinkageValue ::= OCTET STRING (SIZE(9))
     */
    public static final OERDefinition.Builder LinkageValue = OERDefinition.octets(9).typeName("LinkageValue");

    /**
     * GroupLinkageValue ::= SEQUENCE {
     * jValue  OCTET STRING (SIZE(4)),
     * value   OCTET STRING (SIZE(9))
     * }
     */
    public static final OERDefinition.Builder GroupLinkageValue = OERDefinition.seq(
        OERDefinition.octets(4).label("jValue"),
        OERDefinition.octets(9).label("value")).typeName("GroupLinkageValue");

    /**
     * LaId ::= OCTET STRING (SIZE(2))
     */
    public static final OERDefinition.Builder LaId = OERDefinition.octets(2).typeName("LaId");

    /**
     * LinkageSeed ::= OCTET STRING (SIZE(16))
     */
    public static final OERDefinition.Builder LinkageSeed = OERDefinition.octets(16).typeName("LinkageSeed");

    /**
     * Point256 doesn't exist in the spec, it is here to support the creation of EccP256CurvePoint
     */
    public static final OERDefinition.Builder Point256 = OERDefinition.seq(
        OERDefinition.octets(32).label("x"),
        OERDefinition.octets(32).label("y")
    ).typeName("Point256");


    //
    // Location
    //
    /**
     * EccP256CurvePoint ::= CHOICE {
     * x-only           OCTET STRING (SIZE (32)),
     * fill             NULL,
     * compressed-y-0   OCTET STRING (SIZE (32)),
     * compressed-y-1   OCTET STRING (SIZE (32)),
     * uncompressedP256 SEQUENCE  {
     * x OCTET STRING (SIZE (32)),
     * y OCTET STRING (SIZE (32))
     * }
     * }
     */
    public static final OERDefinition.Builder EccP256CurvePoint = OERDefinition.choice(
        OERDefinition.octets(32).label("x-only"),
        OERDefinition.nullValue().label("fill"),
        OERDefinition.octets(32).label("compressed-y-0"),
        OERDefinition.octets(32).label("compressed-y-1"),
        Point256.label("uncompressedP256")
    ).typeName("EccP256CurvePoint");

    /**
     * EcdsaP256Signature ::= SEQUENCE {
     * rSig  EccP256CurvePoint,
     * sSig  OCTET STRING (SIZE (32))
     * }
     */
    public static final OERDefinition.Builder EcdsaP256Signature = OERDefinition.seq(
        EccP256CurvePoint.label("rSig"),
        OERDefinition.octets(32).label("sSig")
    ).typeName("EcdsaP256Signature");

    /**
     * Point384 does not exist in the spec, it is here to support the creation of EccP384CurvePoint.
     */
    public static final OERDefinition.Builder Point384 = OERDefinition.seq(
        OERDefinition.octets(48).label("x"),
        OERDefinition.octets(48).label("y")
    ).typeName("Point384");

    /**
     * EccP384CurvePoint ::= CHOICE  {
     * x-only          OCTET STRING (SIZE (48)),
     * fill            NULL,
     * compressed-y-0  OCTET STRING (SIZE (48)),
     * compressed-y-1  OCTET STRING (SIZE (48)),
     * uncompressedP384 SEQUENCE {
     * x OCTET STRING (SIZE (48)),
     * y OCTET STRING (SIZE (48))
     * }
     * }
     */
    public static final OERDefinition.Builder EccP384CurvePoint = OERDefinition.choice(
        OERDefinition.octets(48).label("x-only"),
        OERDefinition.nullValue().label("fill"),
        OERDefinition.octets(48).label("compressed-y-0"),
        OERDefinition.octets(48).label("compressed-y-1"),
        Point384.label("uncompressedP384")
    ).typeName("EccP384CurvePoint");

    /**
     * EcdsaP384Signature ::= SEQUENCE {
     * rSig  EccP384CurvePoint,
     * sSig  OCTET STRING (SIZE (48))
     * }
     */
    public static final OERDefinition.Builder EcdsaP384Signature =
        OERDefinition.seq(EccP384CurvePoint.label("rSig"),
            OERDefinition.octets(48).label("sSig")
        ).typeName("EcdsaP384Signature");


    /**
     * Signature ::= CHOICE {
     * ecdsaNistP256Signature         EcdsaP256Signature,
     * ecdsaBrainpoolP256r1Signature  EcdsaP256Signature,
     * ...,
     * ecdsaBrainpoolP384r1Signature  EcdsaP384Signature
     * }
     */
    public static final OERDefinition.Builder Signature = OERDefinition.choice(
        EcdsaP256Signature.label("ecdsaNistP256Signature"),
        EcdsaP256Signature.label("ecdsaBrainpoolP256r1Signature"),
        OERDefinition.extension(
            EcdsaP384Signature.label("ecdsaBrainpoolP384r1Signature")
        )
    ).typeName("Signature");
    /**
     * SymmAlgorithm ::= ENUMERATED {
     * aes128Ccm,
     * ...
     * }
     */
    public static final OERDefinition.Builder SymmAlgorithm = OERDefinition.enumeration(
        OERDefinition.enumItem("aes128Ccm"),
        OERDefinition.extension()
    ).typeName("SymmAlgorithm");
    /**
     * HashAlgorithm ::= ENUMERATED {
     * sha256,
     * ...,
     * sha384
     * }
     */
    public static final OERDefinition.Builder HashAlgorithm = OERDefinition.enumeration(
        OERDefinition.enumItem("sha256"),
        OERDefinition.extension(
            OERDefinition.enumItem("sha384")
        )).typeName("HashAlgorithm");
    /**
     * EciesP256EncryptedKey ::= SEQUENCE {
     * v  EccP256CurvePoint,
     * c  OCTET STRING (SIZE (16)),
     * t  OCTET STRING (SIZE (16))
     * }
     */
    public static final OERDefinition.Builder EciesP256EncryptedKey = OERDefinition.seq(
        EccP256CurvePoint.copy().label("v"),
        OERDefinition.octets(16).label("c"),
        OERDefinition.octets(16).label("t")).typeName("EciesP256EncryptedKey");


    /**
     * BasePublicEncryptionKey ::= CHOICE {
     * eciesNistP256         EccP256CurvePoint,
     * eciesBrainpoolP256r1  EccP256CurvePoint,
     * ...
     * }
     */
    public static final OERDefinition.Builder BasePublicEncryptionKey = OERDefinition.choice(
        EccP256CurvePoint.label("eciesNistP256"),
        EccP256CurvePoint.label("eciesBrainpoolP256r1"),
        OERDefinition.extension()
    ).typeName("BasePublicEncryptionKey");

    /**
     * SymmetricEncryptionKey ::= CHOICE {
     * aes128Ccm  OCTET STRING(SIZE(16)),
     * ...
     * }
     */
    public static final OERDefinition.Builder SymmetricEncryptionKey = OERDefinition.choice(
        OERDefinition.octets(16).label("aes128Ccm"),
        OERDefinition.extension()
    ).typeName("SymmetricEncryptionKey");

    /**
     * PublicEncryptionKey ::= SEQUENCE {
     * supportedSymmAlg  SymmAlgorithm,
     * publicKey         BasePublicEncryptionKey
     * }
     */
    public static final OERDefinition.Builder PublicEncryptionKey =
        OERDefinition.seq(SymmAlgorithm.label("supportedSymmAlg"),
            BasePublicEncryptionKey.label("publicKey")
        ).typeName("PublicEncryptionKey");

    /**
     * EncryptionKey ::= CHOICE {
     * public     PublicEncryptionKey,
     * symmetric  SymmetricEncryptionKey
     * }
     */
    public static final OERDefinition.Builder EncryptionKey = OERDefinition.choice(
        PublicEncryptionKey.label("publicOption"), // "public" clashes with reserved word
        SymmetricEncryptionKey.label("symmetric")).typeName("EncryptionKey");

    /**
     * PublicVerificationKey ::= CHOICE {
     * ecdsaNistP256         EccP256CurvePoint,
     * ecdsaBrainpoolP256r1  EccP256CurvePoint,
     * ...,
     * ecdsaBrainpoolP384r1  EccP384CurvePoint
     * }
     */
    public static final OERDefinition.Builder PublicVerificationKey = OERDefinition.choice(
        EccP256CurvePoint.label("ecdsaNistP256"),
        EccP256CurvePoint.label("ecdsaBrainpoolP256r1"),
        OERDefinition.extension(
            EccP384CurvePoint.label("ecdsaBrainpoolP384r1"))).typeName("PublicVerificationKey");
    /**
     * Psid ::= INTEGER (0..MAX)
     */
    public static final OERDefinition.Builder Psid = OERDefinition.integer().rangeToMAXFrom(0).typeName("Psid");
    /**
     * BitmapSsp ::= OCTET STRING (SIZE(0..31))
     */
    public static final OERDefinition.Builder BitmapSsp = OERDefinition.octets(0, 31).typeName("BitmapSsp");
    /**
     * ServiceSpecificPermissions ::= CHOICE {
     * opaque     OCTET STRING (SIZE(0..MAX)),
     * ...,
     * bitmapSsp  BitmapSsp
     * }
     */
    public static final OERDefinition.Builder ServiceSpecificPermissions = OERDefinition.choice(
        OERDefinition.octets().unbounded().label("opaque"),
        OERDefinition.extension(
            BitmapSsp)
    ).typeName("ServiceSpecificPermissions");
    /**
     * PsidSsp ::= SEQUENCE {
     * psid  Psid,
     * ssp   ServiceSpecificPermissions OPTIONAL
     * }
     */
    public static final OERDefinition.Builder PsidSsp =
        OERDefinition.seq(Psid.label("psid"),
            OERDefinition.optional(ServiceSpecificPermissions.label("ssp"))
        ).typeName("PsidSsp");
    /**
     * SequenceOfPsidSsp ::= SEQUENCE OF PsidSsp
     */
    public static final OERDefinition.Builder SequenceOfPsidSsp = OERDefinition.seqof(PsidSsp).typeName("SequenceOfPsidSsp");
    /**
     * SequenceOfPsid ::= SEQUENCE OF Psid
     */
    public static final OERDefinition.Builder SequenceOfPsid = OERDefinition.seqof(Psid).typeName("SequenceOfPsid");
    /**
     * SequenceOfOctetString ::=
     * SEQUENCE (SIZE (0..MAX)) OF OCTET STRING (SIZE(0..MAX))
     */
    public static final OERDefinition.Builder SequenceOfOctetString =
        OERDefinition.seqof(OERDefinition.octets().rangeToMAXFrom(0)).typeName("SequenceOfOctetString");
    /**
     * BitmapSspRange ::= SEQUENCE {
     * sspValue    OCTET STRING (SIZE(1..32)),
     * sspBitmask  OCTET STRING (SIZE(1..32))
     * }
     */
    public static final OERDefinition.Builder BitmapSspRange = OERDefinition.seq(
        OERDefinition.octets(1, 32).label("sspValue"),
        OERDefinition.octets(1, 32).label("sspBitMask")
    ).typeName("BitmapSspRange");
    /**
     * SspRange ::= CHOICE {
     * opaque          SequenceOfOctetString,
     * all             NULL,
     * ... ,
     * bitmapSspRange  BitmapSspRange
     * }
     */
    public static final OERDefinition.Builder SspRange = OERDefinition.choice(
        SequenceOfOctetString.label("opaque"),
        OERDefinition.nullValue().label("all"),
        OERDefinition.extension(
            BitmapSspRange.label("bitmapSspRange")
        )).typeName("SspRange");
    /**
     * PsidSspRange ::= SEQUENCE {
     * psid      Psid,
     * sspRange  SspRange OPTIONAL
     * }
     */
    public static final OERDefinition.Builder PsidSspRange = OERDefinition.seq(
            Psid.label("psid"),
            OERDefinition.optional(SspRange.label("sspRange")))
        .typeName("PsidSspRange");

    //
    // Crypto Structures
    //
    /**
     * SequenceOfPsidSspRange ::= SEQUENCE OF PsidSspRange
     */
    public static final OERDefinition.Builder SequenceOfPsidSspRange = OERDefinition.seqof(PsidSspRange).typeName("SequenceOfPsidSspRange");
    /**
     * SubjectAssurance ::= OCTET STRING (SIZE(1))
     */
    public static final OERDefinition.Builder SubjectAssurance = OERDefinition.octets(1).typeName("SubjectAssurance");
    /**
     * CrlSeries ::= Uint16
     */
    public static final OERDefinition.Builder CrlSeries = UINT16.typeName("CrlSeries");
    public static final OERDefinition.Builder CountryOnly = UINT16.typeName("CountryOnly");
    /**
     * CountryAndRegions ::= SEQUENCE {
     * countryOnly  CountryOnly,
     * regions      SequenceOfUint8
     * }
     */
    public static final OERDefinition.Builder CountryAndRegions =
        OERDefinition.seq(
            CountryOnly.label("countryOnly"),
            SequenceOfUint8.label("regions")
        ).typeName("CountryAndRegions");
    /**
     * RegionAndSubregions ::= SEQUENCE {
     * region      Uint8,
     * subregions  SequenceOfUint16
     * }
     */
    public static final OERDefinition.Builder RegionAndSubregions =
        OERDefinition.seq(
            UINT8.label("region"),
            SequenceOfUint16.label("subregions")
        ).typeName("RegionAndSubregions");

    /**
     * SequenceOfRegionAndSubregions ::= SEQUENCE OF RegionAndSubregions
     */
    public static final OERDefinition.Builder SequenceOfRegionAndSubregions =
        OERDefinition.seqof(RegionAndSubregions).typeName("SequenceOfRegionAndSubregions");

    /**
     * CountryAndSubregions ::= SEQUENCE {
     * country              CountryOnly,
     * regionAndSubregions  SequenceOfRegionAndSubregions
     * }
     */
    public static final OERDefinition.Builder CountryAndSubregions =
        OERDefinition.seq(
            CountryOnly.label("country"),
            SequenceOfRegionAndSubregions.label("regionAndSubregions")
        ).typeName("CountryAndSubregions");

    /**
     * IdentifiedRegion ::= CHOICE {
     * countryOnly           CountryOnly,
     * countryAndRegions     CountryAndRegions,
     * countryAndSubregions  CountryAndSubregions,
     * ...
     * }
     */
    public static final OERDefinition.Builder IdentifiedRegion = OERDefinition.choice(
        CountryOnly.label("countryOnly"),
        CountryAndRegions.label("countryAndRegions"),
        CountryAndSubregions.label("countryAndSubregions"),
        OERDefinition.extension()
    ).typeName("IdentifiedRegion");

    /**
     * SequenceOfIdentifiedRegion ::= SEQUENCE OF IdentifiedRegion
     */
    public static final OERDefinition.Builder SequenceOfIdentifiedRegion = OERDefinition.seqof(IdentifiedRegion).typeName("SequenceOfIdentifiedRegion");
    /**
     * OneEightyDegreeInt ::= INTEGER {
     * min          (-1799999999),
     * max          (1800000000),
     * unknown      (1800000001)
     * } (-1799999999..1800000001)
     */
    public static final OERDefinition.Builder OneEightyDegreeInt = OERDefinition.integer(-1799999999, 1800000001).typeName("OneEightyDegreeInt");
    public static final OERDefinition.Builder KnownLongitude = OneEightyDegreeInt.copy().typeName("KnownLongitude");
    public static final OERDefinition.Builder UnknownLongitude = OERDefinition.integer().validSwitchValue(new ASN1Integer(1800000001)).typeName("UnknownLongitude");
    /**
     * NinetyDegreeInt ::= INTEGER {
     * min         (-900000000),
     * max         (900000000),
     * unknown     (900000001)
     * } (-900000000..900000001)
     */
    public static final OERDefinition.Builder NinetyDegreeInt = OERDefinition.integer(-900000000, 900000001).typeName("NinetyDegreeInt");
    public static final OERDefinition.Builder KnownLatitude = NinetyDegreeInt.copy().typeName("KnownLatitude");
    //
    // PSID / ITS-AID
    //
    public static final OERDefinition.Builder UnknownLatitude = OERDefinition.integer().validSwitchValue(new ASN1Integer(900000001)).typeName("UnknownLatitude");
    public static final OERDefinition.Builder Elevation = UINT16.typeName("Elevation");
    public static final OERDefinition.Builder Longitude = OneEightyDegreeInt.copy().typeName("Longitude");
    public static final OERDefinition.Builder Latitude = NinetyDegreeInt.copy().typeName("Latitude");
    public static final OERDefinition.Builder ThreeDLocation = OERDefinition.seq(
        Latitude.label("latitude"),
        Longitude.label("longitude"),
        Elevation.label("elevation")
    ).typeName("ThreeDLocation");
    /**
     * TwoDLocation ::= SEQUENCE {
     * latitude   Latitude,
     * longitude  Longitude
     * }
     */
    public static final OERDefinition.Builder TwoDLocation = OERDefinition.seq(
        Latitude.label("latitude"),
        Longitude.label("longitude")
    ).typeName("TwoDLocation");

    /**
     * RectangularRegion ::= SEQUENCE {
     * northWest  TwoDLocation,
     * southEast  TwoDLocation
     * }
     */
    public static final OERDefinition.Builder RectangularRegion = OERDefinition.seq(
        TwoDLocation.label("northWest"),
        TwoDLocation.label("southEast")
    ).typeName("RectangularRegion");
    /**
     * SequenceOfRectangularRegion ::= SEQUENCE OF RectangularRegion
     */
    public static final OERDefinition.Builder SequenceOfRectangularRegion = OERDefinition.seqof(RectangularRegion).typeName("SequenceOfRectangularRegion");

    /**
     * CircularRegion ::= SEQUENCE {
     * center  TwoDLocation,
     * radius  Uint16
     * }
     */
    public static final OERDefinition.Builder CircularRegion = OERDefinition.seq(
        TwoDLocation.label("center"),
        UINT16.label("radius")
    ).typeName("CircularRegion");

    /**
     * PolygonalRegion ::= SEQUENCE SIZE (3..MAX) OF TwoDLocation
     * -- treated as sequence of.
     */
    public static final OERDefinition.Builder PolygonalRegion = OERDefinition.seqof(TwoDLocation).rangeToMAXFrom(3).typeName("PolygonalRegion");

    /**
     * GeographicRegion ::= CHOICE {
     * circularRegion     CircularRegion,
     * rectangularRegion  SequenceOfRectangularRegion,
     * polygonalRegion    PolygonalRegion,
     * identifiedRegion   SequenceOfIdentifiedRegion,
     * ...
     * }
     */
    public static final OERDefinition.Builder GeographicRegion = OERDefinition.choice(
        CircularRegion.label("circularRegion"),
        SequenceOfRectangularRegion.label("rectangularRegion"),
        PolygonalRegion.label("polygonalRegion"),
        SequenceOfIdentifiedRegion.label("identifiedRegion"),
        OERDefinition.extension()
    ).typeName("GeographicRegion");
}
