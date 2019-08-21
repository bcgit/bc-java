package org.bouncycastle.pqc.asn1;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;

/**
 * PQC:
 * <p>
 * { iso(1) identifier-organization(3) dod(6) internet(1) private(4) 1 8301 3 1 3 5 3 ... }
 */
public interface PQCObjectIdentifiers
{
    /** 1.3.6.1.4.1.8301.3.1.3.5.3.2 */
    public static final ASN1ObjectIdentifier rainbow = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.5.3.2");

    /** 1.3.6.1.4.1.8301.3.1.3.5.3.2.1 */
    public static final ASN1ObjectIdentifier rainbowWithSha1   = rainbow.branch("1");
    /** 1.3.6.1.4.1.8301.3.1.3.5.3.2.2 */
    public static final ASN1ObjectIdentifier rainbowWithSha224 = rainbow.branch("2");
    /** 1.3.6.1.4.1.8301.3.1.3.5.3.2.3 */
    public static final ASN1ObjectIdentifier rainbowWithSha256 = rainbow.branch("3");
    /** 1.3.6.1.4.1.8301.3.1.3.5.3.2.4 */
    public static final ASN1ObjectIdentifier rainbowWithSha384 = rainbow.branch("4");
    /** 1.3.6.1.4.1.8301.3.1.3.5.3.2.5 */
    public static final ASN1ObjectIdentifier rainbowWithSha512 = rainbow.branch("5");

    /** 1.3.6.1.4.1.8301.3.1.3.3 */
    public static final ASN1ObjectIdentifier gmss = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.3");

    /** 1.3.6.1.4.1.8301.3.1.3.3.1 */
    public static final ASN1ObjectIdentifier gmssWithSha1   = gmss.branch("1");
    /** 1.3.6.1.4.1.8301.3.1.3.3.2 */
    public static final ASN1ObjectIdentifier gmssWithSha224 = gmss.branch("2");
    /** 1.3.6.1.4.1.8301.3.1.3.3.3 */
    public static final ASN1ObjectIdentifier gmssWithSha256 = gmss.branch("3");
    /** 1.3.6.1.4.1.8301.3.1.3.3.4 */
    public static final ASN1ObjectIdentifier gmssWithSha384 = gmss.branch("4");
    /** 1.3.6.1.4.1.8301.3.1.3.3.5 */
    public static final ASN1ObjectIdentifier gmssWithSha512 = gmss.branch("5");

    /** 1.3.6.1.4.1.8301.3.1.3.4.1 */
    public static final ASN1ObjectIdentifier mcEliece       = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.4.1");

    /** 1.3.6.1.4.1.8301.3.1.3.4.2 */
    public static final ASN1ObjectIdentifier mcElieceCca2   = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.4.2");

    public static final ASN1ObjectIdentifier mcElieceFujisaki    = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.4.2.1");
    public static final ASN1ObjectIdentifier mcEliecePointcheval = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.4.2.2");
    public static final ASN1ObjectIdentifier mcElieceKobara_Imai = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.4.2.3");

    public static final ASN1ObjectIdentifier sphincs256 = BCObjectIdentifiers.sphincs256;
    public static final ASN1ObjectIdentifier sphincs256_with_BLAKE512 = BCObjectIdentifiers.sphincs256_with_BLAKE512;
    public static final ASN1ObjectIdentifier sphincs256_with_SHA512 = BCObjectIdentifiers.sphincs256_with_SHA512;
    public static final ASN1ObjectIdentifier sphincs256_with_SHA3_512 = BCObjectIdentifiers.sphincs256_with_SHA3_512;

    public static final ASN1ObjectIdentifier newHope = BCObjectIdentifiers.newHope;

    /**
     * XMSS
     */
    public static final ASN1ObjectIdentifier xmss                      = BCObjectIdentifiers.xmss;
    public static final ASN1ObjectIdentifier xmss_SHA256ph             = BCObjectIdentifiers.xmss_SHA256ph;
    public static final ASN1ObjectIdentifier xmss_SHA512ph             = BCObjectIdentifiers.xmss_SHA512ph;
    public static final ASN1ObjectIdentifier xmss_SHAKE128ph           = BCObjectIdentifiers.xmss_SHAKE128ph;
    public static final ASN1ObjectIdentifier xmss_SHAKE256ph           = BCObjectIdentifiers.xmss_SHAKE256ph;
    public static final ASN1ObjectIdentifier xmss_SHA256               = BCObjectIdentifiers.xmss_SHA256;
    public static final ASN1ObjectIdentifier xmss_SHA512               = BCObjectIdentifiers.xmss_SHA512;
    public static final ASN1ObjectIdentifier xmss_SHAKE128             = BCObjectIdentifiers.xmss_SHAKE128;
    public static final ASN1ObjectIdentifier xmss_SHAKE256             = BCObjectIdentifiers.xmss_SHAKE256;


    /**
     * XMSS^MT
     */
    public static final ASN1ObjectIdentifier xmss_mt                   = BCObjectIdentifiers.xmss_mt;
    public static final ASN1ObjectIdentifier xmss_mt_SHA256ph          = BCObjectIdentifiers.xmss_mt_SHA256ph;
    public static final ASN1ObjectIdentifier xmss_mt_SHA512ph          = BCObjectIdentifiers.xmss_mt_SHA512ph;
    public static final ASN1ObjectIdentifier xmss_mt_SHAKE128ph        = BCObjectIdentifiers.xmss_mt_SHAKE128ph;
    public static final ASN1ObjectIdentifier xmss_mt_SHAKE256ph        = BCObjectIdentifiers.xmss_mt_SHAKE256ph;
    public static final ASN1ObjectIdentifier xmss_mt_SHA256            = BCObjectIdentifiers.xmss_mt_SHA256;
    public static final ASN1ObjectIdentifier xmss_mt_SHA512            = BCObjectIdentifiers.xmss_mt_SHA512;
    public static final ASN1ObjectIdentifier xmss_mt_SHAKE128          = BCObjectIdentifiers.xmss_mt_SHAKE128;
    public static final ASN1ObjectIdentifier xmss_mt_SHAKE256          = BCObjectIdentifiers.xmss_mt_SHAKE256;

    // old OIDs.
    /**
     * @deprecated use xmss_SHA256ph
     */
    public static final ASN1ObjectIdentifier xmss_with_SHA256          = xmss_SHA256ph;
    /**
     * @deprecated use xmss_SHA512ph
     */
    public static final ASN1ObjectIdentifier xmss_with_SHA512 = xmss_SHA512ph;
    /**
     * @deprecated use xmss_SHAKE128ph
     */
    public static final ASN1ObjectIdentifier xmss_with_SHAKE128 = xmss_SHAKE128ph;
    /**
     * @deprecated use xmss_SHAKE256ph
     */
    public static final ASN1ObjectIdentifier xmss_with_SHAKE256        = xmss_SHAKE256ph;

    /**
     * @deprecated use xmss_mt_SHA256ph
     */
    public static final ASN1ObjectIdentifier xmss_mt_with_SHA256          = xmss_mt_SHA256ph;
    /**
     * @deprecated use xmss_mt_SHA512ph
     */
    public static final ASN1ObjectIdentifier xmss_mt_with_SHA512          = xmss_mt_SHA512ph;
    /**
     * @deprecated use xmss_mt_SHAKE128ph
     */
    public static final ASN1ObjectIdentifier xmss_mt_with_SHAKE128        = xmss_mt_SHAKE128;
    /**
     * @deprecated use xmss_mt_SHAKE256ph
     */
    public static final ASN1ObjectIdentifier xmss_mt_with_SHAKE256        = xmss_mt_SHAKE256;

    /**
     * qTESLA
     */
    public static final ASN1ObjectIdentifier qTESLA = BCObjectIdentifiers.qTESLA;
    public static final ASN1ObjectIdentifier qTESLA_p_I = BCObjectIdentifiers.qTESLA_p_I;
    public static final ASN1ObjectIdentifier qTESLA_p_III = BCObjectIdentifiers.qTESLA_p_III;
}
