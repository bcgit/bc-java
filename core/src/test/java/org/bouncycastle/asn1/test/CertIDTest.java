package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.internal.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;

public class CertIDTest
    extends SimpleTest
{
    public String getName()
    {
        return "CertID";
    }

    public void performTest()
        throws Exception
    {
        DEROctetString issuerAHash = new DEROctetString(Strings.toByteArray("IssuerAHash"));
        DEROctetString issuerBHash = new DEROctetString(Strings.toByteArray("IssuerBHash"));
        DEROctetString issuerAKeyHash = new DEROctetString(Strings.toByteArray("IssuerAKeyHash"));
        DEROctetString issuerBKeyHash = new DEROctetString(Strings.toByteArray("IssuerBKeyHash"));

        CertID a = new CertID(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1), issuerAHash, issuerAKeyHash, new ASN1Integer(BigIntegers.ONE));
        CertID b = new CertID(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE), issuerAHash, issuerAKeyHash, new ASN1Integer(BigIntegers.ONE));
        CertID c = new CertID(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, new DEROctetString(new byte[1])), issuerAHash, issuerAKeyHash, new ASN1Integer(BigIntegers.ONE));

        isTrue(a.equals(a));
        isTrue(a.equals(b));
        isTrue(a.hashCode() == b.hashCode());
        isTrue(!a.equals(c));
        isTrue(a.hashCode() != c.hashCode());

        b = new CertID(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1), issuerAHash, issuerAKeyHash, new ASN1Integer(BigIntegers.TWO));
        isTrue(!a.equals(b));
        b = new CertID(new AlgorithmIdentifier(OIWObjectIdentifiers.elGamalAlgorithm), issuerAHash, issuerAKeyHash, new ASN1Integer(BigIntegers.ONE));
        isTrue(!a.equals(b));
        b = new CertID(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1), issuerBHash, issuerAKeyHash, new ASN1Integer(BigIntegers.ONE));
        isTrue(!a.equals(b));
        b = new CertID(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1), issuerAHash, issuerBKeyHash, new ASN1Integer(BigIntegers.ONE));
        isTrue(!a.equals(b));
    }

    public static void main(
        String[] args)
    {
        runTest(new CertIDTest());
    }
}
