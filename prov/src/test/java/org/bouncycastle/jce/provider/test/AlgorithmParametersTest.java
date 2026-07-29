package org.bouncycastle.jce.provider.test;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class AlgorithmParametersTest
    extends SimpleTest
{
    private byte[] dsaParams = Base64.decode(
        "MIGcAkEAjfKklEkidqo9JXWbsGhpy+rA2Dr7jQz3y7gyTw14guXQdi/FtyEOr8Lprawyq3qsSWk9+/g3J"
      + "MLsBzbuMcgCkQIVAMdzIYxzfsjumTtPLe0w9I7azpFfAkBP3Z9K7oNeZMXEXYpqvrMUgVdFjq4lnWJoV8"
      + "Rwe+TERStHTkqSO7sp0lq7EEggVMcuXtarKNsxaJ+qyYv/n1t6");

    private void basicTest(String algorithm, Class algorithmParameterSpec, byte[] asn1Encoded)
        throws Exception
    {
        AlgorithmParameters alg = AlgorithmParameters.getInstance(algorithm, "BC");

        alg.init(asn1Encoded);

        try
        {
            alg.init(asn1Encoded);
            fail("encoded re-initialization not detected");
        }
        catch (IOException e)
        {
            // expected already initialized
        }

        AlgorithmParameterSpec spec = alg.getParameterSpec(algorithmParameterSpec);

        try
        {
            alg.init(spec);
            fail("spec re-initialization not detected");
        }
        catch (InvalidParameterSpecException e)
        {
            // expected already initialized
        }

        // check default
        spec = alg.getParameterSpec(AlgorithmParameterSpec.class);

        try
        {
            spec = alg.getParameterSpec(IvParameterSpec.class);
            fail("wrong spec not detected");
        }
        catch (InvalidParameterSpecException e)
        {
            // expected unknown object
        }

        try
        {
            spec = alg.getParameterSpec(null);
            fail("null spec not detected");
        }
        catch (NullPointerException e)
        {
            // expected unknown object
        }

        alg = AlgorithmParameters.getInstance(algorithm, "BC");

        alg.init(asn1Encoded, "ASN.1");

        alg = AlgorithmParameters.getInstance(algorithm, "BC");

        alg.init(asn1Encoded, null);

        alg = AlgorithmParameters.getInstance(algorithm, "BC");

        try
        {
            alg.init(asn1Encoded, "FRED");
            fail("unknown spec not detected");
        }
        catch (IOException e)
        {
            // expected already initialized
        }
    }

    private void java21NullCheck()
        throws Exception
    {
        try
        {
            AlgorithmParameters algParams = AlgorithmParameters.getInstance("1.2.840.113549.1.1.1", "BC");
            fail("no exception");
        }
        catch (GeneralSecurityException e)
        {
            // okay..
        }
    }

    private void shortIvInitTest()
        throws Exception
    {
        // a 1-byte parameter array whose only byte is 0x04 used to leak an
        // ArrayIndexOutOfBoundsException out of the DER-octet-string detection
        // heuristic in IvAlgorithmParameters.engineInit(byte[]); it must now
        // fall through to the raw-IV store like every other length does.
        AlgorithmParameters alg = AlgorithmParameters.getInstance("AES", "BC");

        alg.init(new byte[]{0x04});

        IvParameterSpec spec = (IvParameterSpec)alg.getParameterSpec(IvParameterSpec.class);

        if (!Arrays.areEqual(new byte[]{0x04}, spec.getIV()))
        {
            fail("short IV not stored as raw IV");
        }

        // also exercise the RAW format path, which routes through engineInit(byte[])
        alg = AlgorithmParameters.getInstance("AES", "BC");

        alg.init(new byte[]{0x04}, "RAW");

        spec = (IvParameterSpec)alg.getParameterSpec(IvParameterSpec.class);

        if (!Arrays.areEqual(new byte[]{0x04}, spec.getIV()))
        {
            fail("short IV not stored as raw IV (RAW format)");
        }
    }

    private void expectMalformedIOException(String algorithm, byte[] malformedEncoding)
        throws Exception
    {
        AlgorithmParameters alg = AlgorithmParameters.getInstance(algorithm, "BC");

        try
        {
            alg.init(malformedEncoding);
            fail(algorithm + ": malformed parameter encoding not detected");
        }
        catch (IOException e)
        {
            // expected: AlgorithmParameters.init(byte[]) is contracted to throw IOException,
            // not the RuntimeException the underlying ASN.1 decode used to leak.
        }
    }

    private void malformedParameterEncodingTest()
        throws Exception
    {
        // A well-formed ASN.1 object of the wrong top-level type (a bare INTEGER) is not a
        // legal encoding for any of these algorithms; every one of these decoders used to
        // leak an IllegalArgumentException from its ASN1Sequence.getInstance(...) dispatch
        // instead of the IOException AlgorithmParameters.init(byte[]) is contracted to throw.
        byte[] bareInteger = new ASN1Integer(5).getEncoded();

        expectMalformedIOException("EC", bareInteger);
        expectMalformedIOException("DSA", bareInteger);
        expectMalformedIOException("DH", bareInteger);
        expectMalformedIOException("ELGAMAL", bareInteger);
        expectMalformedIOException("GCM", bareInteger);
        expectMalformedIOException("CCM", bareInteger);
        expectMalformedIOException("SM4-GCM", bareInteger);

        // RSA OAEP/PSS: an AlgorithmIdentifier with no nested parameters is a legal encoding
        // of an AlgorithmIdentifier in isolation (parameters are OPTIONAL), but the decoder
        // assumes maskGenAlgorithm always carries a nested digest AlgorithmIdentifier and
        // used to let the resulting NullPointerException escape.
        AlgorithmIdentifier hashAlgorithm = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
        AlgorithmIdentifier bareMGF = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1);
        AlgorithmIdentifier pSourceAlgorithm = new AlgorithmIdentifier(
            PKCSObjectIdentifiers.id_pSpecified, new DEROctetString(new byte[0]));

        expectMalformedIOException("OAEP",
            new RSAESOAEPparams(hashAlgorithm, bareMGF, pSourceAlgorithm).getEncoded());
        expectMalformedIOException("PSS",
            new RSASSAPSSparams(hashAlgorithm, bareMGF, new ASN1Integer(20), new ASN1Integer(1)).getEncoded());

        // GOST3410: a 1-element SEQUENCE whose element is not an OBJECT IDENTIFIER used to
        // let the IllegalArgumentException from ASN1ObjectIdentifier.getInstance escape.
        ASN1EncodableVector gostV = new ASN1EncodableVector();
        gostV.add(DERNull.INSTANCE);
        expectMalformedIOException("GOST3410", new DERSequence(gostV).getEncoded());

        // IES: an outer SEQUENCE carrying only the [keySize, nonce] inner SEQUENCE, with no
        // top-level macKeySize INTEGER, used to let the NullPointerException from
        // macKeySize.intValue() escape.
        ASN1EncodableVector inner = new ASN1EncodableVector();
        inner.add(new ASN1Integer(128));
        inner.add(new DEROctetString(new byte[12]));
        ASN1EncodableVector iesV = new ASN1EncodableVector();
        iesV.add(new DERSequence(inner));
        expectMalformedIOException("IES", new DERSequence(iesV).getEncoded());
    }

    public void performTest()
        throws Exception
    {
        basicTest("DSA", DSAParameterSpec.class, dsaParams);
        java21NullCheck();
        shortIvInitTest();
        malformedParameterEncodingTest();

        AlgorithmParameters al = AlgorithmParameters.getInstance("EC", "BC");

        al.init(new ECGenParameterSpec(SECObjectIdentifiers.secp256r1.getId()));

        if (!Arrays.areEqual(Hex.decode("06082a8648ce3d030107"), al.getEncoded()))
        {
             fail("EC param test failed");
        }
    }

    public String getName()
    {
        return "AlgorithmParameters";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new AlgorithmParametersTest());
    }
}
