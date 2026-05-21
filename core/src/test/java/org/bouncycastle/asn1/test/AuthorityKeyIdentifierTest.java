package org.bouncycastle.asn1.test;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.util.test.SimpleTest;

public class AuthorityKeyIdentifierTest
    extends SimpleTest
{
    public String getName()
    {
        return "AuthorityKeyIdentifier";
    }

    public void performTest()
        throws IOException
    {
        validCombinationsParse();
        invalidCombinationsRejected();
        publicConstructorsRejectMismatchedIssuerAndSerial();
    }

    private void validCombinationsParse()
        throws IOException
    {
        // empty SEQUENCE - all fields absent
        AuthorityKeyIdentifier.getInstance(new DERSequence());

        // keyIdentifier only
        AuthorityKeyIdentifier.getInstance(new DERSequence(
            new DERTaggedObject(false, 0, new DEROctetString(new byte[20]))));

        GeneralNames issuer = new GeneralNames(
            new GeneralName(new X500Name("CN=Test")));

        // both authorityCertIssuer and authorityCertSerialNumber present
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERTaggedObject(false, 1, issuer));
        v.add(new DERTaggedObject(false, 2, new ASN1Integer(BigInteger.ONE)));
        AuthorityKeyIdentifier.getInstance(new DERSequence(v));

        // all three fields present
        v = new ASN1EncodableVector();
        v.add(new DERTaggedObject(false, 0, new DEROctetString(new byte[20])));
        v.add(new DERTaggedObject(false, 1, issuer));
        v.add(new DERTaggedObject(false, 2, new ASN1Integer(BigInteger.ONE)));
        AuthorityKeyIdentifier.getInstance(new DERSequence(v));
    }

    private void invalidCombinationsRejected()
    {
        // RFC 5280 sec. 4.2.1.1 violation: authorityCertSerialNumber without
        // authorityCertIssuer (issue #2036).
        ASN1Sequence onlySerial = new DERSequence(
            new DERTaggedObject(false, 2, new ASN1Integer(BigInteger.ONE)));
        try
        {
            AuthorityKeyIdentifier.getInstance(onlySerial);
            fail("authorityCertSerialNumber-only AKI accepted");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("unexpected message: " + e.getMessage(),
                e.getMessage().indexOf("MUST both be present or both be absent") >= 0);
        }

        // authorityCertIssuer without authorityCertSerialNumber
        GeneralNames issuer = new GeneralNames(
            new GeneralName(new X500Name("CN=Test")));
        ASN1Sequence onlyIssuer = new DERSequence(
            new DERTaggedObject(false, 1, issuer));
        try
        {
            AuthorityKeyIdentifier.getInstance(onlyIssuer);
            fail("authorityCertIssuer-only AKI accepted");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("unexpected message: " + e.getMessage(),
                e.getMessage().indexOf("MUST both be present or both be absent") >= 0);
        }

        // keyIdentifier present but only one of the issuer/serial pair
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERTaggedObject(false, 0, new DEROctetString(new byte[20])));
        v.add(new DERTaggedObject(false, 2, new ASN1Integer(BigInteger.ONE)));
        try
        {
            AuthorityKeyIdentifier.getInstance(new DERSequence(v));
            fail("keyId + serial-only AKI accepted");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void publicConstructorsRejectMismatchedIssuerAndSerial()
    {
        GeneralNames issuer = new GeneralNames(
            new GeneralName(new X500Name("CN=Test")));
        byte[] keyId = new byte[20];

        try
        {
            new AuthorityKeyIdentifier(keyId, issuer, null);
            fail("(byte[], GeneralNames, null) accepted");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        try
        {
            new AuthorityKeyIdentifier(keyId, null, BigInteger.ONE);
            fail("(byte[], null, BigInteger) accepted");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        try
        {
            new AuthorityKeyIdentifier(issuer, null);
            fail("(GeneralNames, null) accepted");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        try
        {
            new AuthorityKeyIdentifier((GeneralNames)null, BigInteger.ONE);
            fail("(null, BigInteger) accepted");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        // matched pairs and absent-pair forms still construct successfully
        new AuthorityKeyIdentifier(keyId);
        new AuthorityKeyIdentifier(keyId, null, null);
        new AuthorityKeyIdentifier(keyId, issuer, BigInteger.ONE);
        new AuthorityKeyIdentifier(issuer, BigInteger.ONE);
    }

    public static void main(String[] args)
    {
        runTest(new AuthorityKeyIdentifierTest());
    }
}
