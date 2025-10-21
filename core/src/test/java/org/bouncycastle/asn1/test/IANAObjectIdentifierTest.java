package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.internal.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestResult;

public class IANAObjectIdentifierTest
    extends SimpleTest
{
    public String getName()
    {
        return "IANAObjectIdentifier";
    }

    public void performTest()
        throws Exception
    {
        isEquals("wrong internet", new ASN1ObjectIdentifier("1.3.6.1"), IANAObjectIdentifiers.internet);
        isEquals("wrong id-alg", new ASN1ObjectIdentifier("1.3.6.1.5.5.7.6"), IANAObjectIdentifiers.id_alg);

        isEquals(IANAObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256.getId(), "1.3.6.1.5.5.7.6.37");
        isEquals(IANAObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256.getId(), "1.3.6.1.5.5.7.6.38");
        isEquals(IANAObjectIdentifiers.id_MLDSA44_Ed25519_SHA512.getId(), "1.3.6.1.5.5.7.6.39");
        isEquals(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256.getId(), "1.3.6.1.5.5.7.6.40");
        isEquals(IANAObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA512.getId(), "1.3.6.1.5.5.7.6.41");
        isEquals(IANAObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA512.getId(), "1.3.6.1.5.5.7.6.42");
        isEquals(IANAObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA512.getId(), "1.3.6.1.5.5.7.6.43");
        isEquals(IANAObjectIdentifiers.id_MLDSA65_RSA4096_PKCS15_SHA512.getId(), "1.3.6.1.5.5.7.6.44");
        isEquals(IANAObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA512.getId(), "1.3.6.1.5.5.7.6.45");
        isEquals(IANAObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA512.getId(), "1.3.6.1.5.5.7.6.46");
        isEquals(IANAObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512.getId(), "1.3.6.1.5.5.7.6.47");
        isEquals(IANAObjectIdentifiers.id_MLDSA65_Ed25519_SHA512.getId(), "1.3.6.1.5.5.7.6.48");
        isEquals(IANAObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA512.getId(), "1.3.6.1.5.5.7.6.49");
        isEquals(IANAObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512.getId(), "1.3.6.1.5.5.7.6.50");
        isEquals(IANAObjectIdentifiers.id_MLDSA87_Ed448_SHAKE256.getId(), "1.3.6.1.5.5.7.6.51");
        isEquals(IANAObjectIdentifiers.id_MLDSA87_RSA3072_PSS_SHA512.getId(), "1.3.6.1.5.5.7.6.52");
        isEquals(IANAObjectIdentifiers.id_MLDSA87_RSA4096_PSS_SHA512.getId(), "1.3.6.1.5.5.7.6.53");
        isEquals(IANAObjectIdentifiers.id_MLDSA87_ECDSA_P521_SHA512.getId(), "1.3.6.1.5.5.7.6.54");
    }

    public static void main(
        String[] args)
    {
        IANAObjectIdentifierTest test = new IANAObjectIdentifierTest();
        TestResult result = test.perform();

        System.out.println(result);
    }
}
