package org.bouncycastle.jce.provider.test;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
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

    public void performTest()
        throws Exception
    {
        basicTest("DSA", DSAParameterSpec.class, dsaParams);

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
