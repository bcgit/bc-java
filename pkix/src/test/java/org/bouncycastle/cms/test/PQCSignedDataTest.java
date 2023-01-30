package org.bouncycastle.cms.test;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.Store;

public class PQCSignedDataTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final String BCPQC = BouncyCastlePQCProvider.PROVIDER_NAME;

    boolean DEBUG = true;

    private static String _origDN;
    private static KeyPair _origKP;
    private static X509Certificate _origCert;
    private static KeyPair _origFalconKP;
    private static X509Certificate _origFalconCert;
    private static KeyPair _origPicnicKP;
    private static X509Certificate _origPicnicCert;
    private static KeyPair _origDilithiumKP;
    private static X509Certificate _origDilithiumCert;
    
    private static String _signDN;
    private static KeyPair _signKP;
    private static X509Certificate _signCert;
    private static KeyPair _signFalconKP;
    private static X509Certificate _signFalconCert;
    private static KeyPair _signPicnicKP;
    private static X509Certificate _signPicnicCert;
    private static KeyPair _signDilithiumKP;
    private static X509Certificate _signDilithiumCert;
    
    private static boolean _initialised = false;

    private static final Set noParams = new HashSet();

    static
    {
        noParams.add(BCObjectIdentifiers.sphincs256_with_SHA512);
        noParams.add(BCObjectIdentifiers.sphincs256_with_SHA3_512);
    }

    public PQCSignedDataTest(String name)
    {
        super(name);
    }

    public static void main(String args[])
        throws Exception
    {
        init();

        junit.textui.TestRunner.run(PQCSignedDataTest.class);
    }

    public static Test suite()
        throws Exception
    {
        init();

        return new CMSTestSetup(new TestSuite(PQCSignedDataTest.class));
    }

    public void setUp()
        throws Exception
    {
        init();
    }

    private static void init()
        throws Exception
    {
        if (!_initialised)
        {
            _initialised = true;

            if (Security.getProvider(BC) == null)
            {
                Security.addProvider(new BouncyCastleProvider());
            }
            if (Security.getProvider(BCPQC) == null)
            {
                Security.addProvider(new BouncyCastlePQCProvider());
            }

            _origDN = "O=Bouncy Castle, C=AU";
            _origKP = PQCTestUtil.makeKeyPair();
            _origCert = PQCTestUtil.makeCertificate(_origKP, _origDN, _origKP, _origDN);

            _signDN = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            _signKP = PQCTestUtil.makeKeyPair();
            _signCert = PQCTestUtil.makeCertificate(_signKP, _signDN, _origKP, _origDN);

            _origFalconKP = PQCTestUtil.makeFalconKeyPair();
            _origFalconCert = PQCTestUtil.makeCertificate(_origFalconKP, _origDN, _origFalconKP, _origDN);

            _signFalconKP = PQCTestUtil.makeFalconKeyPair();
            _signFalconCert = PQCTestUtil.makeCertificate(_signFalconKP, _signDN, _origFalconKP, _origDN);

            _origPicnicKP = PQCTestUtil.makePicnicKeyPair();
            _origPicnicCert = PQCTestUtil.makeCertificate(_origPicnicKP, _origDN, _origPicnicKP, _origDN);

            _signPicnicKP = PQCTestUtil.makePicnicKeyPair();
            _signPicnicCert = PQCTestUtil.makeCertificate(_signPicnicKP, _signDN, _origPicnicKP, _origDN);
            
            _origDilithiumKP = PQCTestUtil.makeDilithiumKeyPair();
            _origDilithiumCert = PQCTestUtil.makeCertificate(_origDilithiumKP, _origDN, _origDilithiumKP, _origDN);
            
            _signDilithiumKP = PQCTestUtil.makeDilithiumKeyPair();
            _signDilithiumCert = PQCTestUtil.makeCertificate(_signDilithiumKP, _signDN, _origDilithiumKP, _origDN);
        }
    }

    public void testSPHINCS256Encapsulated()
        throws Exception
    {
        List certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray("Hello World!".getBytes());

        certList.add(_origCert);
        certList.add(_signCert);

        Store certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digCalcProv).build(new JcaContentSignerBuilder("SHA512withSPHINCS256").setProvider(BCPQC).build(_origKP.getPrivate()), _origCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(msg, true);

        ByteArrayInputStream bIn = new ByteArrayInputStream(s.getEncoded());
        ASN1InputStream aIn = new ASN1InputStream(bIn);

        s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

        certs = s.getCertificates();

        SignerInformationStore signers = s.getSignerInfos();

        Collection c = signers.getSigners();
        Iterator it = c.iterator();
        SignerId sid = null;

        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            Collection certCollection = certs.getMatches(signer.getSID());

            Iterator certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert)));

            //
            // check content digest
            //

            byte[] contentDigest = (byte[])gen.getGeneratedDigests().get(signer.getDigestAlgOID());

            AttributeTable table = signer.getSignedAttributes();
            Attribute hash = table.get(CMSAttributes.messageDigest);

            assertTrue(MessageDigest.isEqual(contentDigest, ((ASN1OctetString)hash.getAttrValues().getObjectAt(0)).getOctets()));
        }
    }

    public void testFalconEncapsulated()
        throws Exception
    {
        List certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray("Hello World!".getBytes());

        certList.add(_origFalconCert);
        certList.add(_signFalconCert);

        Store certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digCalcProv).build(new JcaContentSignerBuilder("Falcon-512").setProvider(BCPQC).build(_origFalconKP.getPrivate()), _origFalconCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(msg, true);

        ByteArrayInputStream bIn = new ByteArrayInputStream(s.getEncoded());
        ASN1InputStream aIn = new ASN1InputStream(bIn);

        s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

        certs = s.getCertificates();

        SignerInformationStore signers = s.getSignerInfos();

        Collection c = signers.getSigners();
        Iterator it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            Collection certCollection = certs.getMatches(signer.getSID());

            Iterator certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert)));

            //
            // check content digest
            //

            byte[] contentDigest = (byte[])gen.getGeneratedDigests().get(signer.getDigestAlgOID());

            AttributeTable table = signer.getSignedAttributes();
            Attribute hash = table.get(CMSAttributes.messageDigest);

            assertTrue(MessageDigest.isEqual(contentDigest, ((ASN1OctetString)hash.getAttrValues().getObjectAt(0)).getOctets()));
        }
    }

    public void testPicnicEncapsulated()
            throws Exception
    {
        List certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray("Hello World!".getBytes());

        certList.add(_origPicnicCert);
        certList.add(_signPicnicCert);

        Store certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digCalcProv).build(new JcaContentSignerBuilder("PICNIC").setProvider(BCPQC).build(_origPicnicKP.getPrivate()), _origPicnicCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(msg, true);

        ByteArrayInputStream bIn = new ByteArrayInputStream(s.getEncoded());
        ASN1InputStream aIn = new ASN1InputStream(bIn);

        s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

        certs = s.getCertificates();

        SignerInformationStore signers = s.getSignerInfos();

        Collection c = signers.getSigners();
        Iterator it = c.iterator();


        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            Collection certCollection = certs.getMatches(signer.getSID());

            Iterator certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            cert.getSubjectPublicKeyInfo();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert)));

            //
            // check content digest
            //

            byte[] contentDigest = (byte[])gen.getGeneratedDigests().get(signer.getDigestAlgOID());

            AttributeTable table = signer.getSignedAttributes();
            Attribute hash = table.get(CMSAttributes.messageDigest);

            assertTrue(MessageDigest.isEqual(contentDigest, ((ASN1OctetString)hash.getAttrValues().getObjectAt(0)).getOctets()));
        }
    }
    
    public void testDilithiumEncapsulated()
            throws Exception
    {
        List certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray("Hello World!".getBytes());

        certList.add(_origDilithiumCert);
        certList.add(_signDilithiumCert);

        Store certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digCalcProv).build(new JcaContentSignerBuilder("Dilithium").setProvider(BCPQC).build(_origDilithiumKP.getPrivate()), _origDilithiumCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(msg, true);

        ByteArrayInputStream bIn = new ByteArrayInputStream(s.getEncoded());
        ASN1InputStream aIn = new ASN1InputStream(bIn);

        s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

        certs = s.getCertificates();

        SignerInformationStore signers = s.getSignerInfos();

        Collection c = signers.getSigners();
        Iterator it = c.iterator();


        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            Collection certCollection = certs.getMatches(signer.getSID());

            Iterator certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            cert.getSubjectPublicKeyInfo();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert)));

            //
            // check content digest
            //

            byte[] contentDigest = (byte[])gen.getGeneratedDigests().get(signer.getDigestAlgOID());

            AttributeTable table = signer.getSignedAttributes();
            Attribute hash = table.get(CMSAttributes.messageDigest);

            assertTrue(MessageDigest.isEqual(contentDigest, ((ASN1OctetString)hash.getAttrValues().getObjectAt(0)).getOctets()));
        }
    }
}
