package org.bouncycastle.crypto.test;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.pkcs.DHParameter;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Malformed PrivateKeyInfo and SubjectPublicKeyInfo structures, of the kinds a fuzzer found reaching a
 * ClassCastException, NullPointerException or ArithmeticException in the key factories, are refused with
 * the IllegalArgumentException a malformed structure gets everywhere else in the library.
 */
public class KeyInfoMalformedInputTest
    extends SimpleTest
{
    private static final DHParameter DH_PARAMS = new DHParameter(BigInteger.valueOf(23), BigInteger.valueOf(5), 0);

    public String getName()
    {
        return "KeyInfoMalformedInput";
    }

    public void performTest()
        throws Exception
    {
        // a private key that is not an INTEGER, which the factory used to cast to one
        privateRejected("DH, key not an INTEGER", new PrivateKeyInfo(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.dhKeyAgreement, DH_PARAMS),
            new DERTaggedObject(false, 0, new DEROctetString(new byte[4]))), null);
        privateRejected("DSA, key not an INTEGER", new PrivateKeyInfo(
            new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa),
            new DERTaggedObject(false, 0, new DEROctetString(new byte[4]))), null);

        // parameters the key cannot be read without, absent
        privateRejected("DH, no parameters", new PrivateKeyInfo(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.dhKeyAgreement), new ASN1Integer(7)),
            "DH private key requires algorithm parameters");
        privateRejected("GOST R 34.10-2001, no parameters", new PrivateKeyInfo(
            new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.643.2.2.19")), new DEROctetString(new byte[32])),
            "GOST R 34.10 private key requires algorithm parameters");
        privateRejected("EC, no parameters anywhere", new PrivateKeyInfo(
            new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey), new ECPrivateKey(256, BigIntegers.ONE)),
            "EC private key requires curve parameters");

        // RFC 5915 lets the curve travel in the ECPrivateKey instead of the algorithm parameters
        ECPrivateKeyParameters ecKey = (ECPrivateKeyParameters)PrivateKeyFactory.createKey(new PrivateKeyInfo(
            new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey),
            new ECPrivateKey(256, BigIntegers.TWO, SECObjectIdentifiers.secp256r1)));
        isTrue("curve taken from the ECPrivateKey", ecKey.getParameters().getN().bitLength() == 256);
        isTrue("private value", ecKey.getD().equals(BigIntegers.TWO));

        // a public key that is not an INTEGER, and parameters that are required, absent
        publicRejected("DSA, key not an INTEGER", new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa), new DEROctetString(new byte[4])), null);
        publicRejected("DH, no parameters", new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.dhKeyAgreement), new ASN1Integer(7)),
            "DH public key requires algorithm parameters");
        publicRejected("EC, no parameters", new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey), new byte[]{ 4, 1, 2 }),
            "EC public key requires algorithm parameters");

        // an odd negative modulus passed the parity check and failed in the small factor search
        try
        {
            new RSAKeyParameters(false, BigInteger.valueOf(-15), BigInteger.valueOf(3));
            fail("negative RSA modulus accepted");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("RSA modulus must be positive", e.getMessage());
        }

        // a legacy BIKE private key encoding shorter than the parameter set's h0, h1 and sigma
        try
        {
            org.bouncycastle.pqc.crypto.util.PrivateKeyFactory.createKey(new PrivateKeyInfo(
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.6.1.4.1.22554.5.8.1")),
                new DEROctetString(new byte[32])));
            fail("short BIKE private key accepted");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("'encoding' has invalid length", e.getMessage());
        }

        // a legacy Dilithium private key encoding shorter than the parameter set's
        try
        {
            org.bouncycastle.pqc.crypto.util.PrivateKeyFactory.createKey(new PrivateKeyInfo(
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.6.1.4.1.2.267.12.4.4")),
                new DEROctetString(new byte[64])));
            fail("short Dilithium private key accepted");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("'encoding' has invalid length", e.getMessage());
        }
    }

    private void privateRejected(String label, PrivateKeyInfo info, String message)
        throws Exception
    {
        try
        {
            PrivateKeyFactory.createKey(info);
            fail(label + ": accepted");
        }
        catch (IllegalArgumentException e)
        {
            if (message != null)
            {
                isEquals(label, message, e.getMessage());
            }
        }
    }

    private void publicRejected(String label, SubjectPublicKeyInfo info, String message)
        throws Exception
    {
        try
        {
            PublicKeyFactory.createKey(info);
            fail(label + ": accepted");
        }
        catch (IllegalArgumentException e)
        {
            if (message != null)
            {
                isEquals(label, message, e.getMessage());
            }
        }
    }

    public static void main(String[] args)
    {
        runTest(new KeyInfoMalformedInputTest());
    }
}
