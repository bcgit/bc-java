package org.bouncycastle.its.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.its.ETSISignedDataBuilder;
import org.bouncycastle.its.ETSISignedData;
import org.bouncycastle.its.bc.BcEtsi103097DataVerifierProvider;
import org.bouncycastle.its.bc.BcEtsi103097DataSigner;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097Data_Signed;
import org.bouncycastle.oer.its.ieee1609dot2.HeaderInfo;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Data;
import org.bouncycastle.oer.its.ieee1609dot2.SignedData;
import org.bouncycastle.oer.its.ieee1609dot2.SignedDataPayload;
import org.bouncycastle.oer.its.ieee1609dot2.ToBeSignedData;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Psid;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Time64;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.UINT8;
import org.junit.Test;

public class ETSIDataSignerTest
    extends TestCase
{

    @Test
    public void test()
        throws Exception
    {
        ToBeSignedData beSignedData = ToBeSignedData.builder()
            .setHeaderInfo(
                HeaderInfo.builder().psid(new Psid(10)).generationTime(Time64.now()).build())
            .setPayload(SignedDataPayload.builder()
                .setData(Ieee1609Dot2Data.builder()
                    .setProtocolVersion(new UINT8(3))
                    .setContent(
                        Ieee1609Dot2Content.builder()
                            .unsecuredData(new DEROctetString("The cat sat on the mat".getBytes())).build())
                    .build())
                .build()).createToBeSignedData();


        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        X9ECParameters parameters = NISTNamedCurves.getByOID(SECObjectIdentifiers.secp256r1);
        generator.init(new ECKeyGenerationParameters(new ECNamedDomainParameters(SECObjectIdentifiers.secp256r1, parameters), new SecureRandom()));
        AsymmetricCipherKeyPair kp = generator.generateKeyPair();

        ECPublicKeyParameters publicVerificationKey = (ECPublicKeyParameters)kp.getPublic();
        ECPrivateKeyParameters privateKeyParameters = (ECPrivateKeyParameters)kp.getPrivate();


        ETSISignedDataBuilder signedDataBuilder = new ETSISignedDataBuilder(beSignedData);
        SignedData signedData = signedDataBuilder.getSignedData(new BcEtsi103097DataSigner(privateKeyParameters));

        ETSISignedData signedDataVerifier = new ETSISignedData(signedData);
        assertTrue(signedDataVerifier.signatureValid(new BcEtsi103097DataVerifierProvider(publicVerificationKey)));


        /**
         * EtsiTs103097Data-Signed {ToBeSignedDataContent} ::= EtsiTs103097Data (WITH COMPONENTS {...,
         *   content (WITH COMPONENTS {
         *     signedData (WITH COMPONENTS {...,
         *       tbsData (WITH COMPONENTS {
         *         payload (WITH COMPONENTS {
         *           data (WITH COMPONENTS {...,
         *             content (WITH COMPONENTS {
         *               unsecuredData (CONTAINING ToBeSignedDataContent)
         *             })
         *           }) PRESENT
         *         })
         *       })
         *     })
         *   })
         * })
         */
        EtsiTs103097Data_Signed signed = new EtsiTs103097Data_Signed(
            Ieee1609Dot2Content.builder()
                .signedData(signedData)
                .build()
        );

        System.out.println();

    }
}
