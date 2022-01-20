package org.bouncycastle.oer.its.template;


import java.math.BigInteger;

import org.bouncycastle.oer.OERDefinition;

public class Ieee1609Dot2BaseTypes
{
    public static final OERDefinition.Builder UINT3 = OERDefinition.integer(0, 7);
    public static final OERDefinition.Builder UINT8 = OERDefinition.integer(0, 255);
    public static final OERDefinition.Builder UINT16 = OERDefinition.integer(0, 65535);
    public static final OERDefinition.Builder UINT32 = OERDefinition.integer(0, 4294967295L);
    public static final OERDefinition.Builder UINT64 = OERDefinition.integer(BigInteger.ZERO, new BigInteger("18446744073709551615"));

    public static final OERDefinition.Builder SequenceOfUint16 = OERDefinition.seqof(UINT16);


    //
    // Octet string types
    //
    public static final OERDefinition.Builder HashedId3 = OERDefinition.octets(3).label("HashId3");
    public static final OERDefinition.Builder SequenceOfHashedId3 = OERDefinition.seqof(HashedId3).label("SequenceOfHashedId3");

    public static final OERDefinition.Builder HashedId8 = OERDefinition.octets(8).label("HashId8");
    public static final OERDefinition.Builder HashedId10 = OERDefinition.octets(10).label("HashId10");
    public static final OERDefinition.Builder HashedId32 = OERDefinition.octets(32).label("HashId32");
    public static final OERDefinition.Builder HashedId48 = OERDefinition.octets(48).label("HashId48");


    //
    // Time.
    //
    public static final OERDefinition.Builder Time32 = UINT32.label("Time32");
    public static final OERDefinition.Builder Time64 = UINT64.label("Time64");

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
    ).label("Duration");


    /**
     * ValidityPeriod ::= SEQUENCE {
     * start     Time32,
     * duration  Duration
     * }
     */
    public static final OERDefinition.Builder ValidityPeriod = OERDefinition.seq(Time32, Duration).label("ValidityPeriod");

    //
    // Pseudonym Linkage
    //

    /**
     * IValue ::= Uint16
     */
    public static final OERDefinition.Builder IValue = UINT16.copy().label("IValue");

    /**
     * Hostname ::= UTF8String (SIZE(0..255))
     */
    public static final OERDefinition.Builder Hostname = OERDefinition.utf8String(0, 255).label("Hostname");

    /**
     * LinkageValue ::= OCTET STRING (SIZE(9))
     */
    public static final OERDefinition.Builder LinkageValue = OERDefinition.octets(9).label("LinkageValue");

    /**
     * GroupLinkageValue ::= SEQUENCE {
     * jValue  OCTET STRING (SIZE(4)),
     * value   OCTET STRING (SIZE(9))
     * }
     */
    public static final OERDefinition.Builder GroupLinkageValue = OERDefinition.seq(OERDefinition.octets(4), OERDefinition.octets(9)).label("GroupLinkageValue");

    /**
     * LaId ::= OCTET STRING (SIZE(2))
     */
    public static final OERDefinition.Builder LaId = OERDefinition.octets(2).label("LaId");

    /**
     * LinkageSeed ::= OCTET STRING (SIZE(16))
     */
    public static final OERDefinition.Builder LinkageSeed = OERDefinition.octets(16).label("LinkageSeed");


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
        OERDefinition.octets(32), OERDefinition.nullValue(), OERDefinition.octets(32), OERDefinition.octets(32), OERDefinition.seq(OERDefinition.octets(32), OERDefinition.octets(32))
    ).label("EccP256CurvePoint");
    /**
     * EcdsaP256Signature ::= SEQUENCE {
     * rSig  EccP256CurvePoint,
     * sSig  OCTET STRING (SIZE (32))
     * }
     */
    public static final OERDefinition.Builder EcdsaP256Signature = OERDefinition.seq(EccP256CurvePoint, OERDefinition.octets(32)).label("EcdsaP256Signature");
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
        OERDefinition.octets(48), OERDefinition.nullValue(), OERDefinition.octets(48), OERDefinition.octets(48), OERDefinition.seq(OERDefinition.octets(48), OERDefinition.octets(48))
    ).label("EccP384CurvePoint");
    /**
     * EcdsaP384Signature ::= SEQUENCE {
     * rSig  EccP384CurvePoint,
     * sSig  OCTET STRING (SIZE (48))
     * }
     */
    public static final OERDefinition.Builder EcdsaP384Signature = OERDefinition.seq(EccP384CurvePoint, OERDefinition.octets(48)).label("EcdsaP384Signature");
    /**
     * Signature ::= CHOICE {
     * ecdsaNistP256Signature         EcdsaP256Signature,
     * ecdsaBrainpoolP256r1Signature  EcdsaP256Signature,
     * ...,
     * ecdsaBrainpoolP384r1Signature  EcdsaP384Signature
     * }
     */
    public static final OERDefinition.Builder Signature = OERDefinition.choice(
        EcdsaP256Signature,
        EcdsaP256Signature,
        OERDefinition.extension(),
        EcdsaP384Signature
    ).label("Signature");
    /**
     * SymmAlgorithm ::= ENUMERATED {
     * aes128Ccm,
     * ...
     * }
     */
    public static final OERDefinition.Builder SymmAlgorithm = OERDefinition.enumeration(
        OERDefinition.enumItem("aes128Ccm"),
        OERDefinition.extension()).label("SymmAlgorithm");
    /**
     * HashAlgorithm ::= ENUMERATED {
     * sha256,
     * ...,
     * sha384
     * }
     */
    public static final OERDefinition.Builder HashAlgorithm = OERDefinition.enumeration(
        OERDefinition.enumItem("sha256"),
        OERDefinition.extension(),
        OERDefinition.enumItem("sha384")).label("HashAlgorithm");
    /**
     * EciesP256EncryptedKey ::= SEQUENCE {
     * v  EccP256CurvePoint,
     * c  OCTET STRING (SIZE (16)),
     * t  OCTET STRING (SIZE (16))
     * }
     */
    public static final OERDefinition.Builder EciesP256EncryptedKey = OERDefinition.seq(
        EccP256CurvePoint.copy().label("v(EccP256CurvePoint)"),
        OERDefinition.octets(16).label("c"),
        OERDefinition.octets(16).label("t")).label("EciesP256EncryptedKey");
    /**
     * BasePublicEncryptionKey ::= CHOICE {
     * eciesNistP256         EccP256CurvePoint,
     * eciesBrainpoolP256r1  EccP256CurvePoint,
     * ...
     * }
     */
    public static final OERDefinition.Builder BasePublicEncryptionKey = OERDefinition.choice(
        EccP256CurvePoint,
        EccP256CurvePoint,
        OERDefinition.extension()).label("BasePublicEncryptionKey");

    /**
     * SymmetricEncryptionKey ::= CHOICE {
     * aes128Ccm  OCTET STRING(SIZE(16)),
     * ...
     * }
     */
    public static final OERDefinition.Builder SymmetricEncryptionKey = OERDefinition.choice(
        OERDefinition.octets(16).label("aes128Ccm"),
        OERDefinition.extension()
    ).label("SymmetricEncryptionKey");

    /**
     * PublicEncryptionKey ::= SEQUENCE {
     * supportedSymmAlg  SymmAlgorithm,
     * publicKey         BasePublicEncryptionKey
     * }
     */
    public static final OERDefinition.Builder PublicEncryptionKey = OERDefinition.seq(SymmAlgorithm, BasePublicEncryptionKey).label("PublicEncryptionKey");
    /**
     * EncryptionKey ::= CHOICE {
     * public     PublicEncryptionKey,
     * symmetric  SymmetricEncryptionKey
     * }
     */
    public static final OERDefinition.Builder EncryptionKey = OERDefinition.choice(PublicEncryptionKey.label("public"), SymmetricEncryptionKey.label("symmetric")).label("EncryptionKey");

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
        OERDefinition.extension(),
        EccP384CurvePoint.label("ecdsaBrainpoolP384r1")).label("PublicVerificationKey");
    /**
     * Psid ::= INTEGER (0..MAX)
     */
    public static final OERDefinition.Builder Psid = OERDefinition.integer().rangeToMAXFrom(0).label("Psid");
    /**
     * BitmapSsp ::= OCTET STRING (SIZE(0..31))
     */
    public static final OERDefinition.Builder BitmapSsp = OERDefinition.octets(0, 31).label("BitmapSsp");
    /**
     * ServiceSpecificPermissions ::= CHOICE {
     * opaque     OCTET STRING (SIZE(0..MAX)),
     * ...,
     * bitmapSsp  BitmapSsp
     * }
     */
    public static final OERDefinition.Builder ServiceSpecificPermissions = OERDefinition.choice(
        OERDefinition.octets().unbounded().label("opaque"),
        OERDefinition.extension(),
        BitmapSsp).label("ServiceSpecificPermissions");
    /**
     * PsidSsp ::= SEQUENCE {
     * psid  Psid,
     * ssp   ServiceSpecificPermissions OPTIONAL
     * }
     */
    public static final OERDefinition.Builder PsidSsp = OERDefinition.seq(Psid, OERDefinition.optional(ServiceSpecificPermissions)).label("PsidSsp");
    /**
     * SequenceOfPsidSsp ::= SEQUENCE OF PsidSsp
     */
    public static final OERDefinition.Builder SequenceOfPsidSsp = OERDefinition.seqof(PsidSsp).label("SequenceOfPsidSsp");
    /**
     * SequenceOfPsid ::= SEQUENCE OF Psid
     */
    public static final OERDefinition.Builder SequenceOfPsid = OERDefinition.seqof(Psid).label("SequenceOfPsid");
    /**
     * SequenceOfOctetString ::=
     * SEQUENCE (SIZE (0..MAX)) OF OCTET STRING (SIZE(0..MAX))
     */
    public static final OERDefinition.Builder SequenceOfOctetString = OERDefinition.seqof(OERDefinition.octets().rangeToMAXFrom(0)).label("SequenceOfOctetString");
    /**
     * BitmapSspRange ::= SEQUENCE {
     * sspValue    OCTET STRING (SIZE(1..32)),
     * sspBitmask  OCTET STRING (SIZE(1..32))
     * }
     */
    public static final OERDefinition.Builder BitmapSspRange = OERDefinition.seq(
        OERDefinition.octets(1, 32).label("sspValue"),
        OERDefinition.octets(1, 32).label("sspBitMask")
    ).label("BitmapSspRange");
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
        OERDefinition.extension(),
        BitmapSspRange.label("bitmapSspRange")).label("SspRange");
    /**
     * PsidSspRange ::= SEQUENCE {
     * psid      Psid,
     * sspRange  SspRange OPTIONAL
     * }
     */
    public static final OERDefinition.Builder PsidSspRange = OERDefinition.seq(Psid.label("psid"), OERDefinition.optional(SspRange.label("sspRange"))).label("PsidSspRange");

    //
    // Crypto Structures
    //
    /**
     * SequenceOfPsidSspRange ::= SEQUENCE OF PsidSspRange
     */
    public static final OERDefinition.Builder SequenceOfPsidSspRange = OERDefinition.seqof(PsidSspRange).label("SequenceOfPsidSspRange");
    /**
     * SubjectAssurance ::= OCTET STRING (SIZE(1))
     */
    public static final OERDefinition.Builder SubjectAssurance = OERDefinition.octets(1).label("SubjectAssurance");
    /**
     * CrlSeries ::= Uint16
     */
    public static final OERDefinition.Builder CrlSeries = UINT16.label("CrlSeries");
    public static OERDefinition.Builder CountryOnly = UINT16.label("CountryOnly");
    /**
     * CountryAndRegions ::= SEQUENCE {
     * countryOnly  CountryOnly,
     * regions      SequenceOfUint8
     * }
     */
    public static OERDefinition.Builder CountryAndRegions = OERDefinition.seq(CountryOnly, OERDefinition.seqof(UINT8)).label("CountryAndRegions");
    /**
     * RegionAndSubregions ::= SEQUENCE {
     * region      Uint8,
     * subregions  SequenceOfUint16
     * }
     */
    public static OERDefinition.Builder RegionAndSubregions = OERDefinition.seq(UINT8, OERDefinition.seqof(UINT16)).label("RegionAndSubregions");
    /**
     * SequenceOfRegionAndSubregions ::= SEQUENCE OF RegionAndSubregions
     */
    public static OERDefinition.Builder SequenceOfRegionAndSubregions = OERDefinition.seqof(RegionAndSubregions).label("SequenceOfRegionAndSubregions");
    /**
     * CountryAndSubregions ::= SEQUENCE {
     * country              CountryOnly,
     * regionAndSubregions  SequenceOfRegionAndSubregions
     * }
     */
    public static OERDefinition.Builder CountryAndSubregions = OERDefinition.seq(CountryOnly, SequenceOfRegionAndSubregions).label("CountryAndSubregions");
    /**
     * IdentifiedRegion ::= CHOICE {
     * countryOnly           CountryOnly,
     * countryAndRegions     CountryAndRegions,
     * countryAndSubregions  CountryAndSubregions,
     * ...
     * }
     */
    public static OERDefinition.Builder IdentifiedRegion = OERDefinition.choice(
        CountryOnly,
        CountryAndRegions,
        CountryAndSubregions,
        OERDefinition.extension()).label("IdentifiedRegion");
    /**
     * SequenceOfIdentifiedRegion ::= SEQUENCE OF IdentifiedRegion
     */
    public static OERDefinition.Builder SequenceOfIdentifiedRegion = OERDefinition.seqof(IdentifiedRegion).label("SequenceOfIdentifiedRegion");
    /**
     * OneEightyDegreeInt ::= INTEGER {
     * min          (-1799999999),
     * max          (1800000000),
     * unknown      (1800000001)
     * } (-1799999999..1800000001)
     */
    public static OERDefinition.Builder OneEightyDegreeInt = OERDefinition.integer(-1799999999, 1800000001).label("OneEightyDegreeInt");
    public static OERDefinition.Builder KnownLongitude = OneEightyDegreeInt.copy().label("KnownLongitude(OneEightyDegreeInt)");
    public static OERDefinition.Builder UnknownLongitude = OERDefinition.integer(1800000001).label("UnknownLongitude");
    /**
     * NinetyDegreeInt ::= INTEGER {
     * min         (-900000000),
     * max         (900000000),
     * unknown     (900000001)
     * } (-900000000..900000001)
     */
    public static OERDefinition.Builder NinetyDegreeInt = OERDefinition.integer(-900000000, 900000001).label("NinetyDegreeInt");
    public static OERDefinition.Builder KnownLatitude = NinetyDegreeInt.copy().label("KnownLatitude(NinetyDegreeInt)");
    //
    // PSID / ITS-AID
    //
    public static OERDefinition.Builder UnknownLatitude = OERDefinition.integer(900000001);
    public static OERDefinition.Builder Elevation = UINT16.label("Elevation");
    public static OERDefinition.Builder Longitude = OneEightyDegreeInt.copy().label("Longitude(OneEightyDegreeInt)");
    public static OERDefinition.Builder Latitude = NinetyDegreeInt.copy().label("Latitude(NinetyDegreeInt)");
    public static OERDefinition.Builder ThreeDLocation = OERDefinition.seq(Latitude, Longitude, Elevation).label("ThreeDLocation");
    /**
     * TwoDLocation ::= SEQUENCE {
     * latitude   Latitude,
     * longitude  Longitude
     * }
     */
    public static OERDefinition.Builder TwoDLocation = OERDefinition.seq(Latitude, Longitude).label("TwoDLocation");
    /**
     * RectangularRegion ::= SEQUENCE {
     * northWest  TwoDLocation,
     * southEast  TwoDLocation
     * }
     */
    public static OERDefinition.Builder RectangularRegion = OERDefinition.seq(TwoDLocation, TwoDLocation).label("RectangularRegion");
    /**
     * SequenceOfRectangularRegion ::= SEQUENCE OF RectangularRegion
     */
    public static OERDefinition.Builder SequenceOfRectangularRegion = OERDefinition.seqof(RectangularRegion).label("SequenceOfRectangularRegion");
    /**
     * CircularRegion ::= SEQUENCE {
     * center  TwoDLocation,
     * radius  Uint16
     * }
     */
    public static OERDefinition.Builder CircularRegion = OERDefinition.seq(TwoDLocation, UINT16).label("CircularRegion");
    /**
     * PolygonalRegion ::= SEQUENCE SIZE (3..MAX) OF TwoDLocation
     * -- treated as sequence of.
     */
    public static OERDefinition.Builder PolygonalRegion = OERDefinition.seqof(TwoDLocation).rangeToMAXFrom(3).label("PolygonalRegion");
    /**
     * GeographicRegion ::= CHOICE {
     * circularRegion     CircularRegion,
     * rectangularRegion  SequenceOfRectangularRegion,
     * polygonalRegion    PolygonalRegion,
     * identifiedRegion   SequenceOfIdentifiedRegion,
     * ...
     * }
     */
    public static OERDefinition.Builder GeographicRegion = OERDefinition.choice(
        CircularRegion,
        SequenceOfRectangularRegion,
        PolygonalRegion,
        SequenceOfIdentifiedRegion, OERDefinition.extension()).label("GeographicRegion");
}
