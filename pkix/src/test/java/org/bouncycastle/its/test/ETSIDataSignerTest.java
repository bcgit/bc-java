package org.bouncycastle.its.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

import junit.framework.TestCase;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.its.ETSISignedData;
import org.bouncycastle.its.ETSISignedDataBuilder;
import org.bouncycastle.its.bc.BcEtsi103097DataSigner;
import org.bouncycastle.its.bc.BcEtsi103097DataVerifierProvider;
import org.bouncycastle.its.jcajce.JcaEtsi103097DataSigner;
import org.bouncycastle.its.jcajce.JcaEtsi103097DataVerifierProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Psid;

public class ETSIDataSignerTest
    extends TestCase
{
    public void setUp()
        throws Exception
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testBc()
        throws Exception
    {
//        ToBeSignedData beSignedData = ToBeSignedData.builder()
//            .setHeaderInfo(
//                HeaderInfo.builder().psid(new Psid(10)).generationTime(Time64.now()).build())
//            .setPayload(SignedDataPayload.builder()
//                .setData(Ieee1609Dot2Data.builder()
//                    .setProtocolVersion(new UINT8(3))
//                    .setContent(
//                        Ieee1609Dot2Content.builder()
//                            .unsecuredData(new DEROctetString("The cat sat on the mat".getBytes())).build())
//                    .build())
//                .build()).createToBeSignedData();


        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        X9ECParameters parameters = NISTNamedCurves.getByOID(SECObjectIdentifiers.secp256r1);
        generator.init(new ECKeyGenerationParameters(new ECNamedDomainParameters(SECObjectIdentifiers.secp256r1, parameters), new SecureRandom()));
        AsymmetricCipherKeyPair kp = generator.generateKeyPair();

        ECPublicKeyParameters publicVerificationKey = (ECPublicKeyParameters)kp.getPublic();
        ECPrivateKeyParameters privateKeyParameters = (ECPrivateKeyParameters)kp.getPrivate();

        ETSISignedDataBuilder signedDataBuilder = ETSISignedDataBuilder.builder(new Psid(10))
            .setUnsecuredData("The cat sat on the mat".getBytes());

        ETSISignedData signedData = signedDataBuilder.build(new BcEtsi103097DataSigner(privateKeyParameters));
        assertTrue(signedData.signatureValid(new BcEtsi103097DataVerifierProvider(publicVerificationKey)));

    }

    public void testJca()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();

        ECPublicKey publicVerificationKey = (ECPublicKey)kp.getPublic();
        ECPrivateKey privateKeyParameters = (ECPrivateKey)kp.getPrivate();

        ETSISignedDataBuilder signedDataBuilder = ETSISignedDataBuilder
            .builder(new Psid(10))
            .setUnsecuredData("The cat sat on the mat".getBytes());

        ETSISignedData signedData = signedDataBuilder.build(
            new JcaEtsi103097DataSigner.Builder().setProvider("BC").build(privateKeyParameters));

        assertTrue(signedData.signatureValid(new JcaEtsi103097DataVerifierProvider.Builder().setProvider("BC").build(publicVerificationKey)));
    }
}
