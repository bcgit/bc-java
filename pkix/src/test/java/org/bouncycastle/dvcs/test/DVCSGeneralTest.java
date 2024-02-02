package org.bouncycastle.dvcs.test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.dvcs.CertEtcToken;
import org.bouncycastle.asn1.dvcs.DVCSObjectIdentifiers;
import org.bouncycastle.asn1.dvcs.TargetEtcChain;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.SignerInformationVerifierProvider;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.test.CMSTestUtil;
import org.bouncycastle.dvcs.CCPDRequestBuilder;
import org.bouncycastle.dvcs.CCPDRequestData;
import org.bouncycastle.dvcs.CPDRequestBuilder;
import org.bouncycastle.dvcs.CPDRequestData;
import org.bouncycastle.dvcs.DVCSException;
import org.bouncycastle.dvcs.DVCSRequest;
import org.bouncycastle.dvcs.DVCSRequestInfo;
import org.bouncycastle.dvcs.MessageImprint;
import org.bouncycastle.dvcs.MessageImprintBuilder;
import org.bouncycastle.dvcs.SignedDVCSMessageGenerator;
import org.bouncycastle.dvcs.TargetChain;
import org.bouncycastle.dvcs.VPKCRequestBuilder;
import org.bouncycastle.dvcs.VPKCRequestData;
import org.bouncycastle.dvcs.VSDRequestBuilder;
import org.bouncycastle.dvcs.VSDRequestData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.test.GeneralTest;
import org.bouncycastle.util.Arrays;

public class DVCSGeneralTest
    extends GeneralTest
{
    public static void main(String[] args)
        throws Exception
    {
        DVCSGeneralTest test = new DVCSGeneralTest();
        test.setUp();
        test.init();
        test.testVSDRequest();
        test.testVPKCRequest();
        test.testCCPDRequest();
    }

    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static boolean initialised = false;

    private static String origDN;
    private static KeyPair origKP;
    private static X509Certificate origCert;

    private static String signDN;
    private static KeyPair signKP;
    private static X509Certificate signCert;

    static void init()
        throws Exception
    {
        if (!initialised)
        {
            initialised = true;

            if (Security.getProvider(BC) == null)
            {
                Security.addProvider(new BouncyCastleProvider());
            }
            origDN = "O=Bouncy Castle, C=AU";
            origKP = CMSTestUtil.makeKeyPair();
            origCert = CMSTestUtil.makeCertificate(origKP, origDN, origKP, origDN);

            signDN = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            signKP = CMSTestUtil.makeKeyPair();
            signCert = CMSTestUtil.makeCertificate(signKP, signDN, origKP, origDN);
        }
    }

    public void testCCPDRequest()
        throws Exception
    {
        if (!initialised)
        {
            init();
        }
        SignedDVCSMessageGenerator gen = getSignedDVCSMessageGenerator();

        CCPDRequestBuilder reqBuilder = new CCPDRequestBuilder();
        reqBuilder.setNonce(BigInteger.ONE);
        reqBuilder.setRequester(new GeneralName(new X500Name("CN=Test Requester")));
        reqBuilder.setDVCS(new GeneralName(new X500Name("CN=Test DVCS")));
        reqBuilder.setDataLocations(new GeneralName(new X500Name("CN=Test DataLocations")));

        MessageImprintBuilder imprintBuilder = new MessageImprintBuilder(new SHA1DigestCalculator());

        MessageImprint messageImprint = imprintBuilder.build(new byte[100]);

        CMSSignedData reqMsg = gen.build(reqBuilder.build(messageImprint));

        assertTrue(reqMsg.verifySignatures(new SignerInformationVerifierProvider()
        {
            public SignerInformationVerifier get(SignerId sid)
                throws OperatorCreationException
            {
                return new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(signCert);
            }
        }));

        DVCSRequest request = new DVCSRequest(reqMsg);
        assertNull(request.getTransactionIdentifier());
        DVCSRequestInfo requestInfo = request.getRequestInfo();
        DVCSRequestInfo requestInfo2 = new DVCSRequestInfo(requestInfo.toASN1Structure().getEncoded());
        assertTrue(DVCSRequestInfo.validate(requestInfo, requestInfo2));
        assertEquals(requestInfo.getVersion(), requestInfo2.getVersion());
        assertEquals(BigInteger.ONE, requestInfo2.getNonce());
        assertEquals(requestInfo.getNonce(), requestInfo2.getNonce());
        assertEquals(requestInfo.getRequestTime(), requestInfo2.getRequestTime());
        assertEquals(requestInfo.getRequester(), requestInfo2.getRequester());
        assertEquals(new GeneralName(new X500Name("CN=Test Requester")), requestInfo2.getRequester().getNames()[0]);
        assertEquals(requestInfo.getRequestPolicy(), requestInfo2.getRequestPolicy());
        assertEquals(requestInfo.getDVCSNames(), requestInfo2.getDVCSNames());
        assertEquals(new GeneralName(new X500Name("CN=Test DVCS")), requestInfo2.getDVCSNames().getNames()[0]);
        assertEquals(requestInfo.getDataLocations(), requestInfo2.getDataLocations());
        assertEquals(new GeneralName(new X500Name("CN=Test DataLocations")), requestInfo2.getDataLocations().getNames()[0]);
        CCPDRequestData reqData = (CCPDRequestData)request.getData();

        testException("ContentInfo not a DVCS Request", "DVCSConstructionException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                ContentInfo contentInfo = new ContentInfo(CMSObjectIdentifiers.signedData, new BasicConstraints(true));
                new DVCSRequest(contentInfo);
            }
        });

        testException("Unable to parse content: ", "DVCSConstructionException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                ContentInfo contentInfo = new ContentInfo(DVCSObjectIdentifiers.id_ct_DVCSRequestData, new BasicConstraints(true));
                new DVCSRequest(contentInfo);
            }
        });

        assertTrue(messageImprint.equals(messageImprint));
        assertFalse(messageImprint.equals(reqData));
        assertEquals(messageImprint, reqData.getMessageImprint());
        assertEquals(messageImprint.hashCode(), reqData.getMessageImprint().hashCode());
    }

    private CMSSignedData getWrappedCPDRequest()
        throws OperatorCreationException, CertificateEncodingException, DVCSException, IOException
    {
        SignedDVCSMessageGenerator gen = getSignedDVCSMessageGenerator();

        CPDRequestBuilder reqBuilder = new CPDRequestBuilder();

        return gen.build(reqBuilder.build(new byte[100]));
    }

    public void testCPDRequest()
        throws Exception
    {
        if (!initialised)
        {
            init();
        }
        CMSSignedData reqMsg = getWrappedCPDRequest();

        assertTrue(reqMsg.verifySignatures(new SignerInformationVerifierProvider()
        {
            public SignerInformationVerifier get(SignerId sid)
                throws OperatorCreationException
            {
                return new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(signCert);
            }
        }));

        DVCSRequest request = new DVCSRequest(reqMsg);

        CPDRequestData reqData = (CPDRequestData)request.getData();

        assertTrue(Arrays.areEqual(new byte[100], reqData.getMessage()));
    }

    public void testVPKCRequest()
        throws Exception
    {
        if (!initialised)
        {
            init();
        }
        SignedDVCSMessageGenerator gen = getSignedDVCSMessageGenerator();

        VPKCRequestBuilder reqBuilder = new VPKCRequestBuilder();
        reqBuilder.setDVCS(new GeneralNames(new GeneralName(new X500Name("CN=Test Requester"))));
        reqBuilder.setDataLocations(new GeneralNames(new GeneralName(new X500Name("CN=Test DataLocations"))));
        reqBuilder.addExtension(Extension.basicConstraints, false, new BasicConstraints(true));
        reqBuilder.addTargetChain(new JcaX509CertificateHolder(signCert));

        CMSSignedData reqMsg = gen.build(reqBuilder.build());

        assertTrue(reqMsg.verifySignatures(new SignerInformationVerifierProvider()
        {
            public SignerInformationVerifier get(SignerId sid)
                throws OperatorCreationException
            {
                return new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(signCert);
            }
        }));

        DVCSRequest request = new DVCSRequest(reqMsg);

        VPKCRequestData reqData = (VPKCRequestData)request.getData();

        VPKCRequestBuilder reqBuilder2 = new VPKCRequestBuilder();
        reqBuilder2.setRequestTime(new Date());
        reqBuilder2.addTargetChain((TargetChain)reqData.getCerts().get(0));
        reqBuilder2.addTargetChain(new Extension(Extension.basicConstraints, false, new BasicConstraints(true).getEncoded()));
        CMSSignedData reqMsg2 = gen.build(reqBuilder2.build());
        DVCSRequest request2 = new DVCSRequest(reqMsg2);
        assertEquals(2, ((VPKCRequestData)request2.getData()).getCerts().size());
        assertEquals(new TargetEtcChain(new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, new JcaX509CertificateHolder(signCert).toASN1Structure())), ((TargetChain)reqData.getCerts().get(0)).toASN1Structure());
    }

    public void testVSDRequest()
        throws Exception
    {
        if (!initialised)
        {
            init();
        }
        CMSSignedData message = getWrappedCPDRequest();

        SignedDVCSMessageGenerator gen = getSignedDVCSMessageGenerator();

        VSDRequestBuilder reqBuilder = new VSDRequestBuilder();

        reqBuilder.setRequestTime(new Date());

        CMSSignedData reqMsg = gen.build(reqBuilder.build(message));

        assertTrue(reqMsg.verifySignatures(new SignerInformationVerifierProvider()
        {
            public SignerInformationVerifier get(SignerId sid)
                throws OperatorCreationException
            {
                return new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(signCert);
            }
        }));

        DVCSRequest request = new DVCSRequest(reqMsg);

        final VSDRequestData reqData = (VSDRequestData)request.getData();

        assertEquals(message.toASN1Structure().getContentType(), reqData.getParsedMessage().toASN1Structure().getContentType());

        assertNotNull(reqData.getMessage());
    }

    private SignedDVCSMessageGenerator getSignedDVCSMessageGenerator()
        throws OperatorCreationException, CertificateEncodingException
    {
        CMSSignedDataGenerator sigDataGen = new CMSSignedDataGenerator();

        JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder().setProvider(BC);

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(signKP.getPrivate());

        sigDataGen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(calculatorProviderBuilder.build()).build(contentSigner, signCert));

        return new SignedDVCSMessageGenerator(sigDataGen);
    }
}
