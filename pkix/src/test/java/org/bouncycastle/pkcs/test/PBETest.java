package org.bouncycastle.pkcs.test;

import java.security.Security;

import junit.framework.TestCase;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PBMAC1Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.jcajce.JcePBMac1CalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePBMac1CalculatorProviderBuilder;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class PBETest
    extends TestCase
{
    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testPBESHA256()
        throws Exception
    {
        MacCalculator pbCalculator = new JcePBMac1CalculatorBuilder("HmacSHA256", 256)
            .setIterationCount(1)
            .setSalt(Strings.toByteArray("salt"))
            .setPrf(JcePBMac1CalculatorBuilder.PRF_SHA256)
            .setProvider("BC").build("passwd".toCharArray());

        assertEquals("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc", Hex.toHexString((byte[])pbCalculator.getKey().getRepresentation()));

    }

    public void testPbmac1PrfPropagation() throws OperatorCreationException {
        AlgorithmIdentifier prf = new AlgorithmIdentifier(NISTObjectIdentifiers.id_hmacWithSHA3_512, null);;
        AlgorithmIdentifier protectionAlgorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBMAC1,
            new PBMAC1Params(
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2, new PBKDF2Params("salt".getBytes(), 1234, 64, prf)),
                new AlgorithmIdentifier(NISTObjectIdentifiers.id_hmacWithSHA3_512, null)
            )
        );
        MacCalculator calculator = new JcePBMac1CalculatorProviderBuilder()
                .setProvider(new BouncyCastleProvider()).build().get(protectionAlgorithm, "foobar123".toCharArray());
        AlgorithmIdentifier actualPrf = PBKDF2Params.getInstance(
            PBMAC1Params.getInstance(calculator.getKey().getAlgorithmIdentifier().getParameters()).getKeyDerivationFunc().getParameters()
        ).getPrf();
        assertTrue(prf.equals(actualPrf));
    }

}
