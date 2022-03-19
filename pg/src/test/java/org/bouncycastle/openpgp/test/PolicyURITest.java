package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.sig.PolicyURI;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;

public class PolicyURITest
    extends SimpleTest
{

    public static void main(String[] args)
    {
        runTest(new PolicyURITest());
    }

    @Override
    public String getName()
    {
        return "PolicyURITest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        testGetURI();
        testParsingFromSignature();
    }

    public void testGetURI()
    {
        PolicyURI policyURI = new PolicyURI(true, "https://bouncycastle.org/policy/alice.txt");
        isTrue(policyURI.isCritical());
        isEquals("https://bouncycastle.org/policy/alice.txt", policyURI.getURI());

        policyURI = new PolicyURI(false, "https://bouncycastle.org/policy/bob.txt");
        isTrue(!policyURI.isCritical());
        isEquals("https://bouncycastle.org/policy/bob.txt", policyURI.getURI());
    }

    public void testParsingFromSignature()
        throws IOException
    {
        String signatureWithPolicyUri = "-----BEGIN PGP SIGNATURE-----\n" +
            "\n" +
            "iKQEHxYKAFYFAmIRIAgJEDXXpSQjWzWvFiEEVSc3S9X9kRTsyfjqNdelJCNbNa8u\n" +
            "Gmh0dHBzOi8vZXhhbXBsZS5vcmcvfmFsaWNlL3NpZ25pbmctcG9saWN5LnR4dAAA\n" +
            "NnwBAImA2KdiS/7kLWoQpwc+A6N2PtAvLxG0gkZmGzYgRWvGAP9g4GLAA/GQ0plr\n" +
            "Xn7uLnOG49S1fFA9P+R1Dd8Qoa4+Dg==\n" +
            "=OPUu\n" +
            "-----END PGP SIGNATURE-----\n";

        ByteArrayInputStream byteIn = new ByteArrayInputStream(Strings.toByteArray(signatureWithPolicyUri));
        ArmoredInputStream armorIn = new ArmoredInputStream(byteIn);
        PGPObjectFactory objectFactory = new BcPGPObjectFactory(armorIn);

        PGPSignatureList signatures = (PGPSignatureList)objectFactory.nextObject();
        PGPSignature signature = signatures.get(0);

        PolicyURI policyURI = signature.getHashedSubPackets().getPolicyURI();
        isEquals("https://example.org/~alice/signing-policy.txt", policyURI.getURI());

        PolicyURI other = new PolicyURI(false, "https://example.org/~alice/signing-policy.txt");

        ByteArrayOutputStream first = new ByteArrayOutputStream();
        policyURI.encode(first);

        ByteArrayOutputStream second = new ByteArrayOutputStream();
        other.encode(second);

        areEqual(first.toByteArray(), second.toByteArray());
    }
}
