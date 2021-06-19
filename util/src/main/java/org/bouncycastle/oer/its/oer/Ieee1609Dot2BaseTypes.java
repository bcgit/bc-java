package org.bouncycastle.oer.its.oer;


import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.oer.OERDefinition;

import static org.bouncycastle.oer.OERDefinition.choice;
import static org.bouncycastle.oer.OERDefinition.enumItem;
import static org.bouncycastle.oer.OERDefinition.enumeration;
import static org.bouncycastle.oer.OERDefinition.extension;
import static org.bouncycastle.oer.OERDefinition.integer;
import static org.bouncycastle.oer.OERDefinition.nullValue;
import static org.bouncycastle.oer.OERDefinition.octets;
import static org.bouncycastle.oer.OERDefinition.optional;
import static org.bouncycastle.oer.OERDefinition.seq;
import static org.bouncycastle.oer.OERDefinition.seqof;


public class Ieee1609Dot2BaseTypes
{
    public static final OERDefinition.Builder UINT3 = integer(0, 7);
    public static final OERDefinition.Builder UINT8 = integer(0, 255);
    public static final OERDefinition.Builder UINT16 = integer(0, 65535);
    public static final OERDefinition.Builder UINT32 = integer(0, 4294967295L);
    public static final OERDefinition.Builder UINT64 = integer(BigInteger.ZERO, new BigInteger("18446744073709551615"));

    public static final OERDefinition.Builder SequenceOfUint16 = seqof(UINT16);


    //
    // Octet string types
    //
    public static final OERDefinition.Builder HashId3 = octets(3).label("HashId3");
    public static final OERDefinition.Builder SequenceOfHashedId3 = seqof(HashId3).label("SequenceOfHashedId3");

    public static final OERDefinition.Builder HashId8 = octets(8).label("HashId8");
    public static final OERDefinition.Builder HashId10 = octets(10).label("HashId10");
    public static final OERDefinition.Builder HashId32 = octets(32).label("HashId32");


    //
    // Time.
    //
    public static final OERDefinition.Builder Time32 = UINT32.label("Time32");
    public static final OERDefinition.Builder Time64 = UINT64.label("Time64");

    public static final OERDefinition.Builder Duration = choice(
        UINT16.label("microseconds"),
        UINT16.label("milliseconds"),
        UINT16.label("seconds"),
        UINT16.label("minutes"),
        UINT16.label("hours"),
        UINT16.label("sixtyHours"),
        UINT16.label("years")
    ).label("Duration");

    public static final OERDefinition.Builder ValidityPeriod = seq(Time32, Duration).label("ValidityPeriod");

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
    public static final OERDefinition.Builder Hostname = octets(9).label("Hostname");

    /**
     * LinkageValue ::= OCTET STRING (SIZE(9))
     */
    public static final OERDefinition.Builder LinkageValue = octets(9).label("LinkageValue");

    /**
     * GroupLinkageValue ::= SEQUENCE {
     * jValue  OCTET STRING (SIZE(4)),
     * value   OCTET STRING (SIZE(9))
     * }
     */
    public static final OERDefinition.Builder GroupLinkageValue = seq(octets(4), octets(9)).label("GroupLinkageValue");

    /**
     * LaId ::= OCTET STRING (SIZE(2))
     */
    public static final OERDefinition.Builder LaId = octets(2).label("LaId");

    /**
     * LinkageSeed ::= OCTET STRING (SIZE(16))
     */
    public static final OERDefinition.Builder LinkageSeed = octets(16).label("LinkageSeed");


    //
    // Location
    //

    public static OERDefinition.Builder CountryOnly = UINT16.label("CountryOnly");

    /**
     * CountryAndRegions ::= SEQUENCE {
     * countryOnly  CountryOnly,
     * regions      SequenceOfUint8
     * }
     */
    public static OERDefinition.Builder CountryAndRegions = seq(CountryOnly, seqof(UINT8)).label("CountryAndRegions");


    /**
     * RegionAndSubregions ::= SEQUENCE {
     * region      Uint8,
     * subregions  SequenceOfUint16
     * }
     */
    public static OERDefinition.Builder RegionAndSubregions = seq(UINT8, seqof(UINT16)).label("RegionAndSubregions");


    /**
     * SequenceOfRegionAndSubregions ::= SEQUENCE OF RegionAndSubregions
     */
    public static OERDefinition.Builder SequenceOfRegionAndSubregions = seqof(RegionAndSubregions).label("SequenceOfRegionAndSubregions");

    /**
     * CountryAndSubregions ::= SEQUENCE {
     * country              CountryOnly,
     * regionAndSubregions  SequenceOfRegionAndSubregions
     * }
     */
    public static OERDefinition.Builder CountryAndSubregions = seq(CountryOnly, SequenceOfRegionAndSubregions).label("CountryAndSubregions");


    /**
     * OneEightyDegreeInt ::= INTEGER {
     * min          (-1799999999),
     * max          (1800000000),
     * unknown      (1800000001)
     * } (-1799999999..1800000001)
     */
    public static OERDefinition.Builder OneEightyDegreeInt = integer(-1799999999, 1800000000, new ASN1Integer(1800000001)).label("OneEightyDegreeInt");

    public static OERDefinition.Builder KnownLongitude = OneEightyDegreeInt.copy().label("KnownLongitude(OneEightyDegreeInt)");

    public static OERDefinition.Builder UnknownLongitude = integer(1800000001).label("UnknownLongitude");


    /**
     * NinetyDegreeInt ::= INTEGER {
     * min         (-900000000),
     * max         (900000000),
     * unknown     (900000001)
     * } (-900000000..900000001)
     */
    public static OERDefinition.Builder NinetyDegreeInt = integer(-900000000, 900000000, new ASN1Integer(900000001)).label("NinetyDegreeInt");

    public static OERDefinition.Builder KnownLatitude = NinetyDegreeInt.copy().label("KnownLatitude(NinetyDegreeInt)");

    public static OERDefinition.Builder UnknownLatitude = integer(900000001);
    ;

    public static OERDefinition.Builder Elevation = UINT16.label("Elevation");

    public static OERDefinition.Builder Longitude = OneEightyDegreeInt.copy().label("Longitude(OneEightyDegreeInt)");

    public static OERDefinition.Builder Latitude = NinetyDegreeInt.copy().label("Latitude(NinetyDegreeInt)");

    public static OERDefinition.Builder ThreeDLocation = seq(Latitude, Longitude, Elevation).label("ThreeDLocation");


    /**
     * TwoDLocation ::= SEQUENCE {
     * latitude   Latitude,
     * longitude  Longitude
     * }
     */
    public static OERDefinition.Builder TwoDLocation = seq(Latitude, Longitude).label("TwoDLocation");


    /**
     * RectangularRegion ::= SEQUENCE {
     * northWest  TwoDLocation,
     * southEast  TwoDLocation
     * }
     */
    public static OERDefinition.Builder RectangularRegion = seq(TwoDLocation, TwoDLocation).label("RectangularRegion");


    /**
     * SequenceOfRectangularRegion ::= SEQUENCE OF RectangularRegion
     */
    public static OERDefinition.Builder SequenceOfRectangularRegion = seq(TwoDLocation, TwoDLocation).label("SequenceOfRectangularRegion");

    /**
     * CircularRegion ::= SEQUENCE {
     * center  TwoDLocation,
     * radius  Uint16
     * }
     */
    public static OERDefinition.Builder CircularRegion = seq(TwoDLocation, UINT16).label("CircularRegion");


    /**
     * PolygonalRegion ::= SEQUENCE SIZE (3..MAX) OF TwoDLocation
     */
    public static OERDefinition.Builder PolygonalRegion = seq(TwoDLocation).rangeToMAX(3).label("PolygonalRegion");


    /**
     * IdentifiedRegion ::= CHOICE {
     * countryOnly           CountryOnly,
     * countryAndRegions     CountryAndRegions,
     * countryAndSubregions  CountryAndSubregions,
     * ...
     * }
     */
    public static OERDefinition.Builder IdentifiedRegion = choice(
        CountryOnly,
        CountryAndRegions,
        CountryAndSubregions,
        extension()).label("IdentifiedRegion");

    /**
     * SequenceOfIdentifiedRegion ::= SEQUENCE OF IdentifiedRegion
     */
    public static OERDefinition.Builder SequenceOfIdentifiedRegion = seqof(IdentifiedRegion).label("SequenceOfIdentifiedRegion");


    /**
     * GeographicRegion ::= CHOICE {
     * circularRegion     CircularRegion,
     * rectangularRegion  SequenceOfRectangularRegion,
     * polygonalRegion    PolygonalRegion,
     * identifiedRegion   SequenceOfIdentifiedRegion,
     * ...
     * }
     */
    public static OERDefinition.Builder GeographicRegion = choice(
        CircularRegion,
        SequenceOfRectangularRegion,
        PolygonalRegion,
        SequenceOfIdentifiedRegion, extension()).label("GeographicRegion");

    //
    // Crypto Structures
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
    public static final OERDefinition.Builder EccP256CurvePoint = choice(
        octets(32), nullValue(), octets(32), octets(32), seq(octets(32), octets(32))
    ).label("EccP256CurvePoint");

    /**
     * EcdsaP256Signature ::= SEQUENCE {
     * rSig  EccP256CurvePoint,
     * sSig  OCTET STRING (SIZE (32))
     * }
     */
    public static final OERDefinition.Builder EcdsaP256Signature = seq(EccP256CurvePoint, octets(32)).label("EcdsaP256Signature");

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
    public static final OERDefinition.Builder EccP384CurvePoint = choice(
        octets(48), nullValue(), octets(48), octets(48), seq(octets(48), octets(48))
    ).label("EccP384CurvePoint");


    /**
     * EcdsaP384Signature ::= SEQUENCE {
     * rSig  EccP384CurvePoint,
     * sSig  OCTET STRING (SIZE (48))
     * }
     */
    public static final OERDefinition.Builder EcdsaP384Signature = seq(EccP384CurvePoint, octets(48)).label("EcdsaP384Signature");


    /**
     * Signature ::= CHOICE {
     * ecdsaNistP256Signature         EcdsaP256Signature,
     * ecdsaBrainpoolP256r1Signature  EcdsaP256Signature,
     * ...,
     * ecdsaBrainpoolP384r1Signature  EcdsaP384Signature
     * }
     */
    public static final OERDefinition.Builder Signature = choice(
        EcdsaP256Signature,
        EcdsaP256Signature,
        extension(),
        EcdsaP384Signature
    ).label("Signature");


    /**
     * SymmAlgorithm ::= ENUMERATED {
     * aes128Ccm,
     * ...
     * }
     */
    public static final OERDefinition.Builder SymmAlgorithm = enumeration(
        enumItem("aes128Ccm"),
        extension()).label("SymmAlgorithm");

    /**
     * HashAlgorithm ::= ENUMERATED {
     * sha256,
     * ...,
     * sha384
     * }
     */
    public static final OERDefinition.Builder HashAlgorithm = enumeration(
        enumItem("sha256"),
        extension(),
        enumItem("sha384")).label("HashAlgorithm");

    /**
     * EciesP256EncryptedKey ::= SEQUENCE {
     * v  EccP256CurvePoint,
     * c  OCTET STRING (SIZE (16)),
     * t  OCTET STRING (SIZE (16))
     * }
     */
    public static final OERDefinition.Builder EciesP256EncryptedKey = seq(
        EccP256CurvePoint.copy().label("v(EccP256CurvePoint)"),
        octets(16).label("c"),
        octets(16).label("t")).label("EciesP256EncryptedKey");


    /**
     * BasePublicEncryptionKey ::= CHOICE {
     * eciesNistP256         EccP256CurvePoint,
     * eciesBrainpoolP256r1  EccP256CurvePoint,
     * ...
     * }
     */
    public static final OERDefinition.Builder BasePublicEncryptionKey = choice(
        EccP256CurvePoint,
        EccP256CurvePoint,
        extension()).label("BasePublicEncryptionKey");

    /**
     * PublicEncryptionKey ::= SEQUENCE {
     * supportedSymmAlg  SymmAlgorithm,
     * publicKey         BasePublicEncryptionKey
     * }
     */
    public static final OERDefinition.Builder PublicEncryptionKey = seq(SymmAlgorithm, BasePublicEncryptionKey).label("PublicEncryptionKey");

    /**
     * SymmetricEncryptionKey ::= CHOICE {
     * aes128Ccm  OCTET STRING(SIZE(16)),
     * ...
     * }
     */
    public static final OERDefinition.Builder SymmetricEncryptionKey = choice(
        octets(16).label("aes128Ccm"),
        extension()
    ).label("SymmetricEncryptionKey");


    /**
     * EncryptionKey ::= CHOICE {
     * public     PublicEncryptionKey,
     * symmetric  SymmetricEncryptionKey
     * }
     */
    public static final OERDefinition.Builder EncryptionKey = choice(PublicEncryptionKey.label("public"), SymmetricEncryptionKey.label("symmetric")).label("EncryptionKey");

    /**
     * PublicVerificationKey ::= CHOICE {
     * ecdsaNistP256         EccP256CurvePoint,
     * ecdsaBrainpoolP256r1  EccP256CurvePoint,
     * ...,
     * ecdsaBrainpoolP384r1  EccP384CurvePoint
     * }
     */
    public static final OERDefinition.Builder PublicVerificationKey = choice(
        EccP256CurvePoint.label("ecdsaNistP256"),
        EccP256CurvePoint.label("ecdsaBrainpoolP256r1"),
        extension(),
        EccP384CurvePoint.label("ecdsaBrainpoolP384r1")).label("PublicVerificationKey");


    //
    // PSID / ITS-AID
    //

    /**
     * Psid ::= INTEGER (0..MAX)
     */
    public static final OERDefinition.Builder Psid = integer().rangeToMAX(0).label("Psid");


    /**
     * BitmapSsp ::= OCTET STRING (SIZE(0..31))
     */
    public static final OERDefinition.Builder BitmapSsp = octets(0, 31).label("BitmapSsp");

    /**
     * ServiceSpecificPermissions ::= CHOICE {
     * opaque     OCTET STRING (SIZE(0..MAX)),
     * ...,
     * bitmapSsp  BitmapSsp
     * }
     */
    public static final OERDefinition.Builder ServiceSpecificPermissions = choice(
        octets().unbounded().label("opaque"),
        extension(),
        BitmapSsp).label("ServiceSpecificPermissions");

    /**
     * PsidSsp ::= SEQUENCE {
     * psid  Psid,
     * ssp   ServiceSpecificPermissions OPTIONAL
     * }
     */
    public static final OERDefinition.Builder PsidSsp = seq(Psid, optional(ServiceSpecificPermissions)).label("PsidSsp");

    /**
     * SequenceOfPsidSsp ::= SEQUENCE OF PsidSsp
     */
    public static final OERDefinition.Builder SequenceOfPsidSsp = seqof(PsidSsp).label("SequenceOfPsidSsp");

    /**
     * SequenceOfPsid ::= SEQUENCE OF Psid
     */
    public static final OERDefinition.Builder SequenceOfPsid = seqof(Psid).label("SequenceOfPsid");

    /**
     * SequenceOfOctetString ::=
     * SEQUENCE (SIZE (0..MAX)) OF OCTET STRING (SIZE(0..MAX))
     */
    public static final OERDefinition.Builder SequenceOfOctetString = seqof(octets().rangeToMAX(0)).label("SequenceOfOctetString");

    /**
     * BitmapSspRange ::= SEQUENCE {
     * sspValue    OCTET STRING (SIZE(1..32)),
     * sspBitmask  OCTET STRING (SIZE(1..32))
     * }
     */
    public static final OERDefinition.Builder BitmapSspRange = seq(
        octets(1, 32).label("sspValue"),
        octets(1, 32).label("sspBitMask")
    ).label("BitmapSspRange");

    /**
     * SspRange ::= CHOICE {
     * opaque          SequenceOfOctetString,
     * all             NULL,
     * ... ,
     * bitmapSspRange  BitmapSspRange
     * }
     */
    public static final OERDefinition.Builder SspRange = choice(
        SequenceOfOctetString.label("opaque"),
        nullValue().label("all"),
        extension(),
        BitmapSspRange.label("bitmapSspRange")).label("SspRange");

    /**
     * PsidSspRange ::= SEQUENCE {
     * psid      Psid,
     * sspRange  SspRange OPTIONAL
     * }
     */
    public static final OERDefinition.Builder PsidSspRange = seq(Psid.label("psid"), optional(SspRange.label("sspRange"))).label("PsidSspRange");

    /**
     * SequenceOfPsidSspRange ::= SEQUENCE OF PsidSspRange
     */
    public static final OERDefinition.Builder SequenceOfPsidSspRange = seqof(PsidSspRange).label("SequenceOfPsidSspRange");

    /**
     * SubjectAssurance ::= OCTET STRING (SIZE(1))
     */
    public static final OERDefinition.Builder SubjectAssurance = octets(1).label("SubjectAssurance");

    /**
     * CrlSeries ::= Uint16
     */
    public static final OERDefinition.Builder CrlSeries = UINT16.label("CrlSeries");
}
