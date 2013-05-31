package org.bouncycastle.cms.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.cms.CMSCompressedDataStreamGenerator;
import org.bouncycastle.cms.CMSDigestedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;

public class MiscDataStreamTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static byte[] data = Base64.decode(
        "TUlNRS1WZXJzaW9uOiAxLjAKQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi9v" +
        "Y3RldC1zdHJlYW0KQ29udGVudC1UcmFuc2Zlci1FbmNvZGluZzogYmluYXJ5" +
        "CkNvbnRlbnQtRGlzcG9zaXRpb246IGF0dGFjaG1lbnQ7IGZpbGVuYW1lPWRv" +
        "Yy5iaW4KClRoaXMgaXMgYSB2ZXJ5IGh1Z2Ugc2VjcmV0LCBtYWRlIHdpdGgg" +
        "b3BlbnNzbAoKCgo=");

    private static byte[] digestedData = Base64.decode(
        "MIIBGAYJKoZIhvcNAQcFoIIBCTCCAQUCAQAwCwYJYIZIAWUDBAIBMIHQBgkq"
      + "hkiG9w0BBwGggcIEgb9NSU1FLVZlcnNpb246IDEuMApDb250ZW50LVR5cGU6"
      + "IGFwcGxpY2F0aW9uL29jdGV0LXN0cmVhbQpDb250ZW50LVRyYW5zZmVyLUVu"
      + "Y29kaW5nOiBiaW5hcnkKQ29udGVudC1EaXNwb3NpdGlvbjogYXR0YWNobWVu"
      + "dDsgZmlsZW5hbWU9ZG9jLmJpbgoKVGhpcyBpcyBhIHZlcnkgaHVnZSBzZWNy"
      + "ZXQsIG1hZGUgd2l0aCBvcGVuc3NsCgoKCgQgHLG72tSYW0LgcxOA474iwdCv"
      + "KyhnaV4RloWTAvkq+do=");

    private static final String TEST_MESSAGE = "Hello World!";
    private static String          _signDN;
    private static KeyPair         _signKP;
    private static X509Certificate _signCert;

    private static String          _origDN;
    private static KeyPair         _origKP;
    private static X509Certificate _origCert;

    private static String          _reciDN;
    private static KeyPair         _reciKP;
    private static X509Certificate _reciCert;

    private static KeyPair         _origDsaKP;
    private static X509Certificate _origDsaCert;

    private static X509CRL         _signCrl;
    private static X509CRL         _origCrl;

    private static boolean         _initialised = false;

    private static final JcaX509CertSelectorConverter selectorConverter = new JcaX509CertSelectorConverter();

    public MiscDataStreamTest(String name)
    {
        super(name);
    }

    private static void init()
        throws Exception
    {
        if (!_initialised)
        {
            _initialised = true;

            _signDN   = "O=Bouncy Castle, C=AU";
            _signKP   = CMSTestUtil.makeKeyPair();
            _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);

            _origDN   = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            _origKP   = CMSTestUtil.makeKeyPair();
            _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _signKP, _signDN);

            _origDsaKP   = CMSTestUtil.makeDsaKeyPair();
            _origDsaCert = CMSTestUtil.makeCertificate(_origDsaKP, _origDN, _signKP, _signDN);

            _reciDN   = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            _reciKP   = CMSTestUtil.makeKeyPair();
            _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);

            _signCrl  = CMSTestUtil.makeCrl(_signKP);
            _origCrl  = CMSTestUtil.makeCrl(_origKP);
        }
    }

    private void verifySignatures(CMSSignedDataParser sp, byte[] contentDigest)
        throws Exception
    {
        CertStore               certStore = sp.getCertificatesAndCRLs("Collection", BC);
        SignerInformationStore  signers = sp.getSignerInfos();

        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certStore.getCertificates(selectorConverter.getCertSelector(signer.getSID()));

            Iterator        certIt = certCollection.iterator();
            X509Certificate cert = (X509Certificate)certIt.next();

            assertEquals(true, signer.verify(cert, BC));

            if (contentDigest != null)
            {
                assertTrue(MessageDigest.isEqual(contentDigest, signer.getContentDigest()));
            }
        }

        Collection certColl = certStore.getCertificates(null);
        Collection crlColl = certStore.getCRLs(null);

        assertEquals(certColl.size(), sp.getCertificates("Collection", BC).getMatches(null).size());
        assertEquals(crlColl.size(), sp.getCRLs("Collection", BC).getMatches(null).size());
    }

    private void verifySignatures(CMSSignedDataParser sp)
        throws Exception
    {
        verifySignatures(sp, null);
    }

    private void verifyEncodedData(ByteArrayOutputStream bOut)
        throws Exception
    {
        CMSSignedDataParser sp;
        sp = new CMSSignedDataParser(bOut.toByteArray());

        sp.getSignedContent().drain();

        verifySignatures(sp);

        sp.close();
    }

    private void checkSigParseable(byte[] sig)
        throws Exception
    {
        CMSSignedDataParser sp = new CMSSignedDataParser(sig);
        sp.getVersion();
        CMSTypedStream sc = sp.getSignedContent();
        if (sc != null)
        {
            sc.drain();
        }
        sp.getCertificatesAndCRLs("Collection", BC);
        sp.getSignerInfos();
        sp.close();
    }

    public void testSHA1WithRSA()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        certList.add(_origCert);
        certList.add(_signCert);

        certList.add(_signCrl);
        certList.add(_origCrl);

        CertStore           certsAndCrls = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), BC);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataStreamGenerator.DIGEST_SHA1, BC);

        gen.addCertificatesAndCRLs(certsAndCrls);

        OutputStream sigOut = gen.open(bOut);

        CMSCompressedDataStreamGenerator cGen = new CMSCompressedDataStreamGenerator();

        OutputStream cOut = cGen.open(sigOut, CMSCompressedDataStreamGenerator.ZLIB);

        cOut.write(TEST_MESSAGE.getBytes());

        cOut.close();

        sigOut.close();

        checkSigParseable(bOut.toByteArray());

        // generate compressed stream
        ByteArrayOutputStream cDataOut = new ByteArrayOutputStream();
        
        cOut = cGen.open(cDataOut, CMSCompressedDataStreamGenerator.ZLIB);

        cOut.write(TEST_MESSAGE.getBytes());

        cOut.close();

        CMSSignedDataParser     sp = new CMSSignedDataParser(
                new CMSTypedStream(new ByteArrayInputStream(cDataOut.toByteArray())), bOut.toByteArray());

        sp.getSignedContent().drain();

        //
        // compute expected content digest
        //
        MessageDigest md = MessageDigest.getInstance("SHA1", BC);

        verifySignatures(sp, md.digest(cDataOut.toByteArray()));
    }

    public void testDigestedData()
        throws Exception
    {
        CMSDigestedData digData = new CMSDigestedData(digestedData);

        assertTrue(Arrays.areEqual(data, (byte[])digData.getDigestedContent().getContent()));

        assertTrue(digData.verify(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()));
    }

    public static Test suite()
        throws Exception
    {
        init();

        return new CMSTestSetup(new TestSuite(MiscDataStreamTest.class));
    }
}