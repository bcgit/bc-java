package org.bouncycastle.pqc.asn1;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface PQCObjectIdentifiers
{
    public static final ASN1ObjectIdentifier rainbow = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.5.3.2");

    public static final ASN1ObjectIdentifier rainbowWithSha1 = rainbow.branch("1");
    public static final ASN1ObjectIdentifier rainbowWithSha224 = rainbow.branch("2");
    public static final ASN1ObjectIdentifier rainbowWithSha256 = rainbow.branch("3");
    public static final ASN1ObjectIdentifier rainbowWithSha384 = rainbow.branch("4");
    public static final ASN1ObjectIdentifier rainbowWithSha512 = rainbow.branch("5");

    public static final ASN1ObjectIdentifier gmss = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.3");

    public static final ASN1ObjectIdentifier gmssWithSha1 = gmss.branch("1");
    public static final ASN1ObjectIdentifier gmssWithSha224 = gmss.branch("2");
    public static final ASN1ObjectIdentifier gmssWithSha256 = gmss.branch("3");
    public static final ASN1ObjectIdentifier gmssWithSha384 = gmss.branch("4");
    public static final ASN1ObjectIdentifier gmssWithSha512 = gmss.branch("5");

    public static final ASN1ObjectIdentifier mcEliece = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.4.1");

    public static final ASN1ObjectIdentifier mcElieceCca2 = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.4.2");

}
