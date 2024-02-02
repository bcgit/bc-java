package org.bouncycastle.cert.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Arrays;
import java.util.Date;
import java.util.Locale;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AltSignatureValue;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.Target;
import org.bouncycastle.asn1.x509.TargetInformation;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V2Form;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.AttributeCertificateHolder;
import org.bouncycastle.cert.AttributeCertificateIssuer;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CRLEntryHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v2AttributeCertificateBuilder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.bc.BcX509v1CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509v3CertificateBuilder;
import org.bouncycastle.cert.dane.DANEEntry;
import org.bouncycastle.cert.dane.DANEEntryFactory;
import org.bouncycastle.cert.dane.DANEException;
import org.bouncycastle.cert.dane.TruncatingDigestCalculator;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.selector.X509AttributeCertificateHolderSelector;
import org.bouncycastle.cert.selector.X509AttributeCertificateHolderSelectorBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.spec.CompositeAlgorithmSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcDSAContentSignerBuilder;
import org.bouncycastle.operator.bc.BcDSAContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.bc.BcECContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcEdDSAContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcEdECContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS10CertificationRequest;
import org.bouncycastle.pkcs.bc.BcPKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.LMSKeyGenParameterSpec;
import org.bouncycastle.test.GeneralTest;
import org.bouncycastle.util.encoders.Hex;

public class CertGeneralTest
    extends GeneralTest
{
    public static void main(String[] args)
        throws Exception
    {
        CertGeneralTest test = new CertGeneralTest();
        test.setUp();
        test.testPKCS10();
        test.testDane();
        test.testCRLCompositeCreation();
        test.testCRLCreation2();
        test.testBcPKCS10();
        test.testEd25519BcBuilder();
        test.testCheckCRLCreation2();
        test.testCheckCRLCreation1();
        test.testBcX509v3CertificateBuilder();
        test.testDefaultDigestAlgorithmIdentifierFinder();
        test.testSelector();
    }

    private static final RSAPrivateCrtKeySpec RSA_PRIVATE_KEY_SPEC = new RSAPrivateCrtKeySpec(
        new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
        new BigInteger("11", 16),
        new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
        new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
        new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
        new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
        new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
        new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));

    public void testSelector()
        throws Exception
    {
        CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate iCert = (X509Certificate)fact
            .generateCertificate(new ByteArrayInputStream(AttrCertSelectorTest.holderCert));
        X509CertificateHolder iCertHolder = new JcaX509CertificateHolder(iCert);
        assertEquals(iCertHolder.getVersionNumber(), iCertHolder.getVersion());
        assertFalse(iCertHolder.equals(fact));

        //
        // set up the keys
        //
        PrivateKey privKey;

        KeyFactory kFact = KeyFactory.getInstance("RSA", "BC");

        privKey = kFact.generatePrivate(AttrCertSelectorTest.RSA_PRIVATE_KEY_SPEC);

        // Tests for AttributeCertificateHolder
        AttributeCertificateHolder attributeCertificateHolder = new AttributeCertificateHolder(iCertHolder.getSubject(), BigInteger.ONE);
        assertEquals(-1, attributeCertificateHolder.getDigestedObjectType());
        assertNull(attributeCertificateHolder.getDigestAlgorithm());
        assertNull(attributeCertificateHolder.getObjectDigest());
        assertNull(attributeCertificateHolder.getOtherObjectTypeID());

        // Tests for AttributeCertificateIssuer
        AttributeCertificateIssuer attributeCertificateIssuer = new AttributeCertificateIssuer(new X500Name("cn=test"));
        X500Name[] names = attributeCertificateIssuer.getNames();
        assertTrue(attributeCertificateIssuer.equals(attributeCertificateIssuer));
        V2Form form = new V2Form(new GeneralNames(new GeneralName(new X500Name("cn=test"))));
        //assertTrue(attributeCertificateIssuer.match(form));

        X509v2AttributeCertificateBuilder gen = new X509v2AttributeCertificateBuilder(
            attributeCertificateHolder,
            new AttributeCertificateIssuer(new X500Name("cn=test")),
            BigInteger.valueOf(1),
            new Date(System.currentTimeMillis() - 50000),
            new Date(System.currentTimeMillis() + 50000),
            Locale.getDefault());

        // the actual attributes
        GeneralName roleName = new GeneralName(GeneralName.rfc822Name,
            "DAU123456789@test.com");
        ASN1EncodableVector roleSyntax = new ASN1EncodableVector();
        roleSyntax.add(roleName);

        // roleSyntax OID: 2.5.24.72
        gen.addAttribute(new ASN1ObjectIdentifier("2.5.24.72"), new DERSequence(roleSyntax));

        ContentSigner sigGen = new JcaContentSignerBuilder("SHA1WithRSAEncryption").setProvider(BC).build(privKey);

        Target targetName = new Target(Target.targetName, new GeneralName(GeneralName.dNSName,
            "www.test.com"));

        Target targetGroup = new Target(Target.targetGroup, new GeneralName(
            GeneralName.directoryName, "o=Test, ou=Test"));
        Target[] targets = new Target[2];
        targets[0] = targetName;
        targets[1] = targetGroup;
        TargetInformation targetInformation = new TargetInformation(targets);

        assertFalse(gen.hasExtension(Extension.targetInformation));
        // Tests for X509v2AttributeCertificateBuilder
        gen.addExtension(Extension.targetInformation, true, targetInformation.getEncoded());
        gen.addExtension(new Extension(Extension.basicConstraints, true, new BasicConstraints(true).getEncoded()));
        gen.replaceExtension(Extension.basicConstraints, false, new BasicConstraints(false).getEncoded());
        gen.replaceExtension(new Extension(Extension.basicConstraints, false, new BasicConstraints(false).getEncoded()));
        gen.replaceExtension(Extension.basicConstraints, false, new BasicConstraints(false).getEncoded());
        gen.removeExtension(Extension.basicConstraints);


        X509AttributeCertificateHolder aCert = gen.build(sigGen);
        // Tests for X509AttributeCertificateHolder
        assertEquals(2, aCert.getVersion());
        assertNotNull(aCert.getExtensionOIDs());
        assertEquals(PKCSObjectIdentifiers.sha1WithRSAEncryption, aCert.getSignatureAlgorithm().getAlgorithm());
        assertNotNull(aCert.getSignature());
        assertEquals(0, aCert.getAttributes(PKCSObjectIdentifiers.pkcs_9).length);


        gen = new X509v2AttributeCertificateBuilder(aCert);
        assertTrue(gen.hasExtension(Extension.targetInformation));
        assertNotNull(gen.getExtension(Extension.targetInformation));

        X509AttributeCertificateHolderSelectorBuilder sel = new X509AttributeCertificateHolderSelectorBuilder();
        sel.setAttributeCert(aCert);
        sel.setTargetNames(Arrays.asList(new GeneralName(GeneralName.dNSName,
            "www.test.com")));
        sel.setAttributeCertificateValid(null);
        boolean match = sel.build().match(aCert);
        if (!match)
        {
            fail("Selector does not match attribute certificate.");
        }
        sel.setAttributeCert(null);
        match = sel.build().match(aCert);
        if (!match)
        {
            fail("Selector does not match attribute certificate.");
        }
        sel.setHolder(aCert.getHolder());
        match = sel.build().match(aCert);
        if (!match)
        {
            fail("Selector does not match attribute certificate holder.");
        }
        sel.setHolder(null);
        sel.setIssuer(aCert.getIssuer());
        match = sel.build().match(aCert);
        if (!match)
        {
            fail("Selector does not match attribute certificate issuer.");
        }
        sel.setIssuer(null);
        fact = CertificateFactory.getInstance("X.509", "BC");
        X509CertificateHolder iCertholder = new JcaX509CertificateHolder((X509Certificate)fact
            .generateCertificate(new ByteArrayInputStream(AttrCertSelectorTest.holderCert)));
        match = aCert.getHolder().match(iCertholder);

        assertFalse(attributeCertificateIssuer.match(iCertholder));
        assertFalse(aCert.equals(attributeCertificateIssuer));
//        if (!match)
//        {
//            fail("Issuer holder does not match signing certificate of attribute certificate.");
//        }

        sel.setSerialNumber(aCert.getSerialNumber());
        match = sel.build().match(aCert);
        if (!match)
        {
            fail("Selector does not match attribute certificate serial number.");
        }
        Date date = new Date();
        sel.setAttributeCertificateValid(date);
        match = sel.build().match(aCert);
        if (!match)
        {
            fail("Selector does not match attribute certificate time.");
        }

        sel.addTargetName(new GeneralName(2, "www.test.com"));
        match = sel.build().match(aCert);
        if (!match)
        {
            fail("Selector does not match attribute certificate target name.");
        }
        sel.setTargetNames(null);
        sel.addTargetGroup(new GeneralName(4, "o=Test, ou=Test"));
        match = sel.build().match(aCert);
        if (!match)
        {
            fail("Selector does not match attribute certificate target group.");
        }
        sel.setTargetGroups(null);

        X509AttributeCertificateHolderSelector selector = (X509AttributeCertificateHolderSelector)sel.build().clone();
        assertNull(selector.getAttributeCert());
        assertEquals(date, selector.getAttributeCertificateValid());
        assertNull(selector.getHolder());
        assertNull(selector.getIssuer());
        assertEquals(BigInteger.ONE, selector.getSerialNumber());
        assertEquals(0, selector.getTargetNames().size());
        assertEquals(0, selector.getTargetGroups().size());
    }

    public void testDefaultDigestAlgorithmIdentifierFinder()
    {
        final DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();
        assertNotNull(digAlgFinder.find(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig)));
        testException("digest OID is null", "NullPointerException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                assertNull(digAlgFinder.find(ASN1ObjectIdentifier.getInstance(null)));
            }
        });

        assertNull(digAlgFinder.find("test"));
    }

    public void testBcX509v3CertificateBuilder()
    {
        X9ECParameters x9 = ECNamedCurveTable.getByName("prime239v1");
        ECCurve curve = x9.getCurve();
        ECDomainParameters params = new ECDomainParameters(curve, x9.getG(), x9.getN(), x9.getH());

        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(
            new BigInteger("876300101507107567501066130761671078357010671067781776716671676178726717"), // d
            params);

        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            curve.decodePoint(Hex.decode("025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70")), // Q
            params);
        X500NameBuilder builder = createStdBuilder();
        try
        {
            ContentSigner sigGen = new BcECContentSignerBuilder(
                new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA1),
                new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)).build(privKey);
            BcX509v3CertificateBuilder certGen = new BcX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);

            X509CertificateHolder cert = certGen.build(sigGen);
            certGen = new BcX509v3CertificateBuilder(cert, BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);
            cert = certGen.build(sigGen);

            if (!cert.isValidOn(new Date()))
            {
                fail("not valid on date");
            }

            if (!cert.isSignatureValid(new BcECContentVerifierProviderBuilder(new DefaultDigestAlgorithmIdentifierFinder()).build(pubKey)))
            {
                fail("signature invalid");
            }
        }
        catch (Exception e)
        {
            fail("error setting generating cert - " + e.toString());
        }
    }

    private X500NameBuilder createStdBuilder()
    {
        X500NameBuilder builder = new X500NameBuilder(RFC4519Style.INSTANCE);

        builder.addRDN(RFC4519Style.c, "AU");
        builder.addRDN(RFC4519Style.o, "The Legion of the Bouncy Castle");
        builder.addRDN(RFC4519Style.l, "Melbourne");
        builder.addRDN(RFC4519Style.st, "Victoria");
        builder.addRDN(PKCSObjectIdentifiers.pkcs_9_at_emailAddress, "feedback-crypto@bouncycastle.org");

        return builder;
    }

    public void testCheckCRLCreation1()
        throws Exception
    {
        AsymmetricCipherKeyPairGenerator kpg = new RSAKeyPairGenerator();
        RSAKeyGenerationParameters genParam = new RSAKeyGenerationParameters(
            BigInteger.valueOf(0x1001), new SecureRandom(), 1024, 25);

        kpg.init(genParam);

        final AsymmetricCipherKeyPair pair = kpg.generateKeyPair();
        Date now = new Date();

        final AlgorithmIdentifier sigAlg = sigAlgFinder.find("SHA256withRSAEncryption");
        AlgorithmIdentifier digAlg = digAlgFinder.find(sigAlg);

        X509v2CRLBuilder crlGen = new X509v2CRLBuilder(new X500Name("CN=Test CA"), now, Locale.getDefault())
            .setThisUpdate(now, Locale.getDefault());
        crlGen.addCRLEntry(BigInteger.ONE, now, CRLReason.privilegeWithdrawn, new Date(now.getTime() + 200000));
        X509CRLHolder crl = crlGen.build(new BcRSAContentSignerBuilder(sigAlg, digAlg).build(pair.getPrivate()));
        assertNull(crl.getNextUpdate());

        crlGen.setNextUpdate(new Date(now.getTime() + 100000), Locale.getDefault());
        assertFalse(crl.hasExtensions());
        assertNull(crl.getExtension(Extension.basicConstraints));
        assertEquals(0, crl.getExtensionOIDs().size());
        assertEquals(0, crl.getCriticalExtensionOIDs().size());
        assertEquals(0, crl.getNonCriticalExtensionOIDs().size());

        X509CRLEntryHolder entry = crl.getRevokedCertificate(BigInteger.ONE);
        assertNull(entry.getExtension(Extension.basicConstraints));

        crlGen = new X509v2CRLBuilder(new X500Name("CN=Test CA"), new Time(now));


        final X509CRLHolder crl1 = crlGen.build(new BcRSAContentSignerBuilder(sigAlg, digAlg).build(pair.getPrivate()));

        testException("unable to process signature: ", "CertException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                crl1.isSignatureValid(new BcDSAContentVerifierProviderBuilder(digAlgFinder).build(pair.getPublic()));
            }
        });

//        testException("unable to process signature: ", "CertException", new TestExceptionOperation()
//        {
//            @Override
//            public void operation()
//                throws Exception
//            {
//                Ed25519KeyGenerationParameters genParam = new Ed25519KeyGenerationParameters(new SecureRandom());
//                AsymmetricCipherKeyPairGenerator kpg = new Ed25519KeyPairGenerator();
//                kpg.init(genParam);
//
//                AsymmetricCipherKeyPair pair = kpg.generateKeyPair();
//                final X509v2CRLBuilder crlGen = new X509v2CRLBuilder(new X500Name("CN=Test CA"), new Date());
//                AlgorithmIdentifier sigAlg = sigAlgFinder.find("SHA1withDSA");
//                AlgorithmIdentifier digAlg = digAlgFinder.find(sigAlg);
//                X509CRLHolder crl = crlGen.build(new BcRSAContentSignerBuilder(sigAlg, digAlg).build(pair.getPrivate()));
//                crl.isSignatureValid(new BcDSAContentVerifierProviderBuilder(digAlgFinder).build(pair.getPublic()));
//            }
//        });

        BcX509ExtensionUtils extFact = new BcX509ExtensionUtils();

        crlGen.addCRLEntry(BigInteger.ONE, now, CRLReason.privilegeWithdrawn, new Date(now.getTime() + 200000));

        crlGen.addExtension(Extension.authorityKeyIdentifier, false, extFact.createAuthorityKeyIdentifier(pair.getPublic()).getEncoded());
        crlGen.addExtension(new Extension(Extension.basicConstraints, false, new BasicConstraints(false).getEncoded()));
        crlGen.replaceExtension(Extension.basicConstraints, true, new BasicConstraints(true).getEncoded());
        crlGen.replaceExtension(new Extension(Extension.basicConstraints, false, new BasicConstraints(true).getEncoded()));
        crlGen.replaceExtension(Extension.basicConstraints, true, new BasicConstraints(true));


        crl = crlGen.build(new BcRSAContentSignerBuilder(sigAlg, digAlg).build(pair.getPrivate()));

        crl = new X509CRLHolder(new ByteArrayInputStream(crl.getEncoded()));
        assertTrue(crl.hasExtensions());
        assertTrue(crl.equals(crl));
        assertFalse(crl.equals(crlGen));
        if (!crl.getIssuer().equals(new X500Name("CN=Test CA")))
        {
            fail("failed CRL issuer test");
        }

        Extension authExt = crl.getExtension(Extension.authorityKeyIdentifier);

        if (authExt == null)
        {
            fail("failed to find CRL extension");
        }

        AuthorityKeyIdentifier authId = AuthorityKeyIdentifier.getInstance(authExt.getParsedValue());

        entry = crl.getRevokedCertificate(BigInteger.ONE);
        assertNotNull(entry.getRevocationDate());
        assertNotNull(entry.getExtensions());
        assertEquals(entry.getExtensionOIDs().size(), entry.getCriticalExtensionOIDs().size() + entry.getNonCriticalExtensionOIDs().size());

        if (entry == null)
        {
            fail("failed to find CRL entry");
        }

        if (!entry.getSerialNumber().equals(BigInteger.ONE))
        {
            fail("CRL cert serial number does not match");
        }

        if (!entry.hasExtensions())
        {
            fail("CRL entry extension not found");
        }

        Extension ext = entry.getExtension(Extension.reasonCode);

        if (ext != null)
        {
            ASN1Enumerated reasonCode = ASN1Enumerated.getInstance(ext.getParsedValue());

            if (!reasonCode.hasValue(CRLReason.privilegeWithdrawn))
            {
                fail("CRL entry reasonCode wrong");
            }
        }
        else
        {
            fail("CRL entry reasonCode not found");
        }
    }

    public void testCheckCRLCreation2()
        throws Exception
    {
        //
        // set up the keys
        //
        AsymmetricKeyParameter privKey;
        AsymmetricKeyParameter pubKey;

        AsymmetricCipherKeyPairGenerator kpg = new DSAKeyPairGenerator();
        DSAParametersGenerator pGen = new DSAParametersGenerator();

        pGen.init(512, 80, new SecureRandom());

        DSAParameters params = pGen.generateParameters();
        DSAKeyGenerationParameters genParam = new DSAKeyGenerationParameters(new SecureRandom(), params);

        kpg.init(genParam);

        AsymmetricCipherKeyPair pair = kpg.generateKeyPair();

        privKey = (AsymmetricKeyParameter)pair.getPrivate();
        pubKey = (AsymmetricKeyParameter)pair.getPublic();

        //
        // distinguished name table.
        //
        X500NameBuilder builder = createStdBuilder();

        AlgorithmIdentifier sigAlgId = sigAlgFinder.find("SHA1withDSA");
        AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId);

        ContentSigner sigGen = new BcDSAContentSignerBuilder(sigAlgId, digAlgId).build(privKey);
        X509v3CertificateBuilder certGen = new BcX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);


        X509CertificateHolder cert = certGen.build(sigGen);

        assertTrue(cert.isValidOn(new Date()));
        // Test for BcDSAContentVerifierProviderBuilder
        assertTrue(cert.isSignatureValid(new BcDSAContentVerifierProviderBuilder(digAlgFinder).build(cert)));
    }

    public void testEd25519BcBuilder()
        throws Exception
    {
        final AsymmetricKeyParameter privKey;
        AsymmetricKeyParameter pubKey;

        AsymmetricCipherKeyPairGenerator kpg = new Ed25519KeyPairGenerator();
//        DSAParametersGenerator pGen = new DSAParametersGenerator();
//
//        pGen.init(512, 80, new SecureRandom());

        Ed25519KeyGenerationParameters genParam = new Ed25519KeyGenerationParameters(new SecureRandom());

        kpg.init(genParam);

        AsymmetricCipherKeyPair pair = kpg.generateKeyPair();

        privKey = (AsymmetricKeyParameter)pair.getPrivate();
        pubKey = (AsymmetricKeyParameter)pair.getPublic();

        //
        // distinguished name table.
        //
        X500NameBuilder builder = createStdBuilder();

        AlgorithmIdentifier sigAlgId = sigAlgFinder.find("Ed25519");

        testException("unknown signature type", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                AlgorithmIdentifier sigAlgId = sigAlgFinder.find("SHA1withDSA");
                ContentSigner sigGen = new BcEdECContentSignerBuilder(sigAlgId).build(privKey);
            }
        });

        ContentSigner sigGen = new BcEdECContentSignerBuilder(sigAlgId).build(privKey);
        X509v3CertificateBuilder certGen = new BcX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);


        X509CertificateHolder cert = certGen.build(sigGen);

        assertTrue(cert.isValidOn(new Date()));

        assertTrue(cert.isSignatureValid(new BcEdDSAContentVerifierProviderBuilder().build(pubKey)));


        //
        // create the certificate - version 1
        //
        sigAlgId = sigAlgFinder.find("Ed25519");

        sigGen = new BcEdECContentSignerBuilder(sigAlgId).build(privKey);
        X509v1CertificateBuilder certGen1 = new BcX509v1CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);

        cert = certGen1.build(sigGen);

        assertTrue(cert.isValidOn(new Date()));

        assertTrue(cert.isSignatureValid(new BcEdDSAContentVerifierProviderBuilder().build(cert)));

        AsymmetricKeyParameter certPubKey = PublicKeyFactory.createKey(cert.getSubjectPublicKeyInfo());

        assertTrue(cert.isSignatureValid(new BcEdDSAContentVerifierProviderBuilder().build(certPubKey)));

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509");

        X509Certificate x509cert = (X509Certificate)fact.generateCertificate(bIn);
    }


    public void testBcPKCS10()
        throws Exception
    {
        int keySize = 512;
        String keyName = "RSA";
        String sigName = "SHA1withRSA";
        AsymmetricCipherKeyPairGenerator kpg = new RSAKeyPairGenerator();
        RSAKeyGenerationParameters genParam = new RSAKeyGenerationParameters(
            BigInteger.valueOf(0x1001), new SecureRandom(), keySize, 25);

        kpg.init(genParam);

        final AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        final ExtensionsGenerator extGen = new ExtensionsGenerator();
        BcX509ExtensionUtils extFact = new BcX509ExtensionUtils();

        Target targetName = new Target(Target.targetName, new GeneralName(GeneralName.dNSName,
            "www.test.com"));
        Target targetGroup = new Target(Target.targetGroup, new GeneralName(
            GeneralName.directoryName, "o=Test, ou=Test"));
        Target[] targets = new Target[2];
        targets[0] = targetName;
        targets[1] = targetGroup;
        TargetInformation targetInformation = new TargetInformation(targets);
        extGen.addExtension(Extension.authorityKeyIdentifier, false, extFact.createAuthorityKeyIdentifier(kp.getPublic()).getEncoded());
        extGen.addExtension(Extension.targetInformation, true, targetInformation.getEncoded());
        extGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        extGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        X500NameBuilder x500NameBld = new X500NameBuilder(RFC4519Style.INSTANCE);

        x500NameBld.addRDN(RFC4519Style.c, "AU");
        x500NameBld.addRDN(RFC4519Style.o, "The Legion of the Bouncy Castle");
        x500NameBld.addRDN(RFC4519Style.l, "Melbourne");
        x500NameBld.addRDN(RFC4519Style.st, "Victoria");
        x500NameBld.addRDN(PKCSObjectIdentifiers.pkcs_9_at_emailAddress, "feedback-crypto@bouncycastle.org");

        X500Name subject = x500NameBld.build();

        PKCS10CertificationRequestBuilder requestBuilder = new PKCS10CertificationRequestBuilder(new BcPKCS10CertificationRequestBuilder(subject, kp.getPublic()));

        DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        final DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();

        AlgorithmIdentifier sigAlgId = sigAlgFinder.find("SHA1withRSA");

        AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId);

        final BcContentSignerBuilder contentSignerBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId)
            .setSecureRandom(CryptoServicesRegistrar.getSecureRandom());

        PKCS10CertificationRequest req1 = requestBuilder.build(contentSignerBuilder.build(kp.getPrivate()));
        assertEquals(0, req1.getAttributes().length);
        assertEquals(0, req1.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest).length);
        BcPKCS10CertificationRequest req2 = new BcPKCS10CertificationRequest(req1.getEncoded());

        if (!req2.isSignatureValid(new BcRSAContentVerifierProviderBuilder(digAlgFinder).build(kp.getPublic())))
        {
            fail(sigName + ": Failed verify check.");
        }

        if (!org.bouncycastle.util.Arrays.areEqual(req2.getSubjectPublicKeyInfo().getEncoded(), req1.getSubjectPublicKeyInfo().getEncoded()))
        {
            fail(keyName + ": Failed public key check.");
        }

        final PKCS10CertificationRequest p1 = new BcPKCS10CertificationRequestBuilder(
            new X500Name("cn=csr"), kp.getPublic())
            .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new ASN1Encodable[]{extGen.generate()})
            .build(contentSignerBuilder.build(kp.getPrivate()));

        testException("no alternate public key present", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                p1.isAltSignatureValid(new BcRSAContentVerifierProviderBuilder(digAlgFinder).build(kp.getPublic()));
            }
        });

        X500NameBuilder builder = createStdBuilder();
        AlgorithmIdentifier sigAlgId_rsa = sigAlgFinder.find("SHA1withRSA");

        AlgorithmIdentifier digAlgId_rsa = digAlgFinder.find(sigAlgId_rsa);

        ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId_rsa, digAlgId_rsa).build(kp.getPrivate());
        X509v3CertificateBuilder certGen = new BcX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1),
            new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), kp.getPublic());

        X509CertificateHolder cert = certGen.build(sigGen);
        PKCS10CertificationRequest p2 = new BcPKCS10CertificationRequestBuilder(
            new X500Name("cn=csr"), kp.getPublic())
            .setAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new ASN1Encodable[]{extGen.generate()})
            .build(contentSignerBuilder.build(kp.getPrivate()), cert.getSubjectPublicKeyInfo(), contentSignerBuilder.build(kp.getPrivate()));

        BcPKCS10CertificationRequest p4 = new BcPKCS10CertificationRequest(p2.toASN1Structure());
        testException(" is already set", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                PKCS10CertificationRequest p1 = new BcPKCS10CertificationRequestBuilder(
                    new X500Name("cn=csr"), kp.getPublic())
                    .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate())
                    .setAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate())
                    .build(contentSignerBuilder.build(kp.getPrivate()));
            }
        });

        testException(" is already set", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                PKCS10CertificationRequest p1 = new BcPKCS10CertificationRequestBuilder(
                    new X500Name("cn=csr"), kp.getPublic())
                    .setAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate())
                    .setAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new ASN1Encodable[]{extGen.generate()})
                    .build(contentSignerBuilder.build(kp.getPrivate()));
            }
        });

        assertFalse(p1.equals(p4));
        assertTrue(p1.equals(p1));
        assertFalse(p1.equals(kp));
        BcPKCS10CertificationRequest p5 = new BcPKCS10CertificationRequest(p2);
        assertEquals(p2.hashCode(), p5.hashCode());

        assertEquals(4, p2.getRequestedExtensions().getExtensionOIDs().length);
        p2 = new BcPKCS10CertificationRequestBuilder(
            new X500Name("cn=csr"), kp.getPublic())
            .setAttribute(PKCSObjectIdentifiers.pkcs_9, new ASN1Encodable[]{extGen.generate()})
            .build(contentSignerBuilder.build(kp.getPrivate()), cert.getSubjectPublicKeyInfo(), contentSignerBuilder.build(kp.getPrivate()));
        assertNull(p2.getRequestedExtensions());

        extGen.addExtension(Extension.biometricInfo, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        p2 = new BcPKCS10CertificationRequestBuilder(
            new X500Name("cn=csr"), kp.getPublic())
            .setAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new ASN1Encodable[]{extGen.generate()})
            .build(contentSignerBuilder.build(kp.getPrivate()), cert.getSubjectPublicKeyInfo(), contentSignerBuilder.build(kp.getPrivate()));
        assertEquals(5, p2.getRequestedExtensions().getExtensionOIDs().length);

    }

    public void testCRLCreation2()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", BC);

        Date now = new Date();
        KeyPair pair = kpGen.generateKeyPair();
        PrivateKey privKey = pair.getPrivate();
        PublicKey pubKey = pair.getPublic();
        X509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(new X500Principal("CN=Test CA"), now);

        crlGen.setNextUpdate(new Date(now.getTime() + 100000));

        Vector extOids = new Vector();
        Vector extValues = new Vector();

        CRLReason crlReason = CRLReason.lookup(CRLReason.privilegeWithdrawn);

        try
        {
            extOids.addElement(Extension.reasonCode);
            extValues.addElement(new Extension(Extension.reasonCode, false, new DEROctetString(crlReason.getEncoded())));
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("error encoding reason: " + e);
        }

        Extensions entryExtensions = generateExtensions(extOids, extValues);

        crlGen.addCRLEntry(BigInteger.ONE, now, entryExtensions);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils(new SHA1DigestCalculator());

        crlGen.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(pair.getPublic(), new X500Principal("CN=Dummy Trust Anchor"), BigInteger.ONE));
        crlGen.replaceExtension(Extension.authorityKeyIdentifier, true, extUtils.createAuthorityKeyIdentifier(pair.getPublic(), new X500Principal("CN=Dummy Trust Anchor"), BigInteger.valueOf(2)));
        final X509CRLHolder crlHolder = crlGen.build(new JcaContentSignerBuilder("SHA256withRSAEncryption").setProvider(BC).build(pair.getPrivate()));

        X509CRL crl = new JcaX509CRLConverter().setProvider(new BouncyCastleProvider()).getCRL(crlHolder);
        crlGen = new JcaX509v2CRLBuilder(crl);
        crl = new JcaX509CRLConverter().setProvider(BC).getCRL(
            crlGen.build(new JcaContentSignerBuilder("SHA256withRSAEncryption")
                .setProvider(BC).build(pair.getPrivate())));
        assertEquals("X.509 not found", testException("cannot create factory: ", "ExCRLException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                X509CRL crl = new JcaX509CRLConverter().setProvider(new BouncyCastlePQCProvider()).getCRL(crlHolder);
            }
        }).getCause().getMessage());


        crl.verify(pair.getPublic(), BC);

        if (!crl.getIssuerX500Principal().equals(new X500Principal("CN=Test CA")))
        {
            fail("failed CRL issuer test");
        }

        byte[] authExt = crl.getExtensionValue(Extension.authorityKeyIdentifier.getId());

        if (authExt == null)
        {
            fail("failed to find CRL extension");
        }

        AuthorityKeyIdentifier authId = AuthorityKeyIdentifier.getInstance(ASN1OctetString.getInstance(authExt).getOctets());

        X509CRLEntry entry = crl.getRevokedCertificate(BigInteger.ONE);

        if (entry == null)
        {
            fail("failed to find CRL entry");
        }

        if (!entry.getSerialNumber().equals(BigInteger.ONE))
        {
            fail("CRL cert serial number does not match");
        }

        if (!entry.hasExtensions())
        {
            fail("CRL entry extension not found");
        }

        byte[] ext = entry.getExtensionValue(Extension.reasonCode.getId());

        if (ext != null)
        {
            ASN1Enumerated reasonCode = (ASN1Enumerated)fromExtensionValue(ext);

            if (!reasonCode.hasValue(CRLReason.privilegeWithdrawn))
            {
                fail("CRL entry reasonCode wrong");
            }
        }
        else
        {
            fail("CRL entry reasonCode not found");
        }

        crlGen = new X509v2CRLBuilder(crlHolder);

        crlGen.setThisUpdate(new Date(crlHolder.getThisUpdate().getTime() + 50000));
        crlGen.setNextUpdate(new Date(crlHolder.getNextUpdate().getTime() + 100000));

        X509CRLHolder hldr2 = crlGen.build(new JcaContentSignerBuilder("SHA256withRSAEncryption").setProvider(BC).build(pair.getPrivate()));

        assertEquals(hldr2.getThisUpdate().getTime(), crlHolder.getThisUpdate().getTime() + 50000);
        assertEquals(hldr2.getNextUpdate().getTime(), crlHolder.getNextUpdate().getTime() + 100000);


        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256withRSAEncryption").setProvider(BC).build(privKey);
        JcaX509v1CertificateBuilder certGen = new JcaX509v1CertificateBuilder(
            new X500Principal("CN=Dummy Issuer"),
            BigInteger.valueOf(1),
            new Date(System.currentTimeMillis() - 50000),
            new Date(System.currentTimeMillis() + 50000),
            new X500Principal("CN=Dummy Subject"),
            pubKey);


        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));
        JcaX509ExtensionUtils.getIssuerAlternativeNames(cert);
        cert.checkValidity(new Date());

        cert.verify(pubKey);

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509", BC);

        cert = (X509Certificate)fact.generateCertificate(bIn);

        cert.getEncoded();
    }

    private Extensions generateExtensions(Vector oids, Vector values)
        throws IOException
    {
        ExtensionsGenerator extGen = new ExtensionsGenerator();

        for (int i = 0; i != oids.size(); i++)
        {
            Extension ext = (Extension)values.elementAt(i);

            extGen.addExtension((ASN1ObjectIdentifier)oids.elementAt(i), ext.isCritical(), ext.getParsedValue());
        }

        return extGen.generate();
    }

    private static ASN1Primitive fromExtensionValue(
        byte[] encodedValue)
        throws IOException
    {
        ASN1OctetString octs = (ASN1OctetString)ASN1Primitive.fromByteArray(encodedValue);

        return ASN1Primitive.fromByteArray(octs.getOctets());
    }

    public void testCRLCompositeCreation()
        throws Exception
    {
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC", BC);

        ecKpg.initialize(new ECGenParameterSpec("P-256"));

        KeyPair ecKp = ecKpg.generateKeyPair();

        PrivateKey ecPriv = ecKp.getPrivate();
        PublicKey ecPub = ecKp.getPublic();

        KeyPairGenerator ecKpg2 = KeyPairGenerator.getInstance("EC", BC);

        ecKpg2.initialize(new ECGenParameterSpec("P-256"));

        KeyPair ecKp2 = ecKpg2.generateKeyPair();

        PrivateKey ecPriv2 = ecKp2.getPrivate();
        PublicKey ecPub2 = ecKp2.getPublic();

//        KeyPairGenerator lmsKpg = KeyPairGenerator.getInstance("LMS", "BCPQC");
//
//        lmsKpg.initialize(new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1));
//
//        KeyPair lmsKp = lmsKpg.generateKeyPair();
//
//        PrivateKey lmsPriv = lmsKp.getPrivate();
//        PublicKey lmsPub = lmsKp.getPublic();
        testException("cannot build with the same algorithm name added", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                CompositeAlgorithmSpec compAlgSpec = new CompositeAlgorithmSpec.Builder()
                    .add("SHA256withECDSA")
                    .add("SHA256withECDSA")
                    .build();
            }
        });


        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BC);

        kpg.initialize(2048, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        PrivateKey privKey = kp.getPrivate();
        PublicKey pubKey = kp.getPublic();

        ContentSigner signer2 = new JcaContentSignerBuilder(
            "RSAPSS",
            new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 20, 1))
            .setProvider(BC).build(kp.getPrivate());

        CompositePublicKey compPub = new CompositePublicKey(ecPub, pubKey);
        final CompositePrivateKey compPrivKey = new CompositePrivateKey(ecPriv, privKey);
        testException("cannot build with the same algorithm name added", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                CompositeAlgorithmSpec compAlgSpec = new CompositeAlgorithmSpec.Builder()
                    .add("RSAPSS", new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 20, 1))
                    .add("RSASSA-PSS", new PSSParameterSpec("SHA-512", "MGF1", new MGF1ParameterSpec("SHA-512"), 0, 1))
                    .build();
                ContentSigner sigGen = new JcaContentSignerBuilder("Composite",
                    compAlgSpec).setProvider(BC)
                    .build(compPrivKey);
            }
        });

        testException("The algorithm name does not match the parameter specification", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                CompositeAlgorithmSpec compAlgSpec = new CompositeAlgorithmSpec.Builder()
                    .add("RSA", new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 20, 1))
                    .add("RSASSA-PSS", new PSSParameterSpec("SHA-512", "MGF1", new MGF1ParameterSpec("SHA-512"), 0, 1))
                    .build();
                ContentSigner sigGen = new JcaContentSignerBuilder("Composite",
                    compAlgSpec).setProvider(BC)
                    .build(compPrivKey);
            }
        });


        testException("unrecognized parameterSpec", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                CompositeAlgorithmSpec compAlgSpec = new CompositeAlgorithmSpec.Builder()
                    .add("RSA", new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n24_h5, LMOtsParameters.sha256_n24_w1))
                    .add("RSASSA-PSS", new PSSParameterSpec("SHA-512", "MGF1", new MGF1ParameterSpec("SHA-512"), 0, 1))
                    .build();
                ContentSigner sigGen = new JcaContentSignerBuilder("Composite",
                    compAlgSpec).setProvider(BC)
                    .build(compPrivKey);
            }
        });

        testException("unknown sigParamSpec: ", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new JcaContentSignerBuilder("test", new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n24_h5, LMOtsParameters.sha256_n24_w1));
            }
        });

//        CompositePublicKey compPub = new CompositePublicKey(pubKey, pubKey2);
//        CompositePrivateKey compPrivKey = new CompositePrivateKey(privKey, privKey2);
        CompositeAlgorithmSpec compAlgSpec = new CompositeAlgorithmSpec.Builder()
            .add("SHA256withECDSA")
            .add("RSASSA-PSS", new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 0, 1))
            .build();

        ContentSigner sigGen = new JcaContentSignerBuilder("Composite",
            compAlgSpec).setProvider(BC)
            .setSecureRandom(CryptoServicesRegistrar.getSecureRandom())
            .build(compPrivKey);


        Date now = new Date();

        X509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(new X500Principal("CN=Test CA"), now);

        crlGen.setNextUpdate(new Date(now.getTime() + 100000));

        Vector extOids = new Vector();
        Vector extValues = new Vector();

        CRLReason crlReason = CRLReason.lookup(CRLReason.privilegeWithdrawn);

        try
        {
            extOids.addElement(Extension.reasonCode);
            extValues.addElement(new Extension(Extension.reasonCode, false, new DEROctetString(crlReason.getEncoded())));
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("error encoding reason: " + e);
        }

        Extensions entryExtensions = generateExtensions(extOids, extValues);

        crlGen.addCRLEntry(BigInteger.ONE, now, entryExtensions);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

//        crlGen.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(pubKey));
        crlGen.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(ecPub));

        X509CRLHolder crlHolder = crlGen.build(sigGen);

        X509CRL crl = new JcaX509CRLConverter().setProvider(BC).getCRL(crlHolder);

        // comp test
        crl.verify(compPub);

        // null comp test
        try
        {
            crl.verify(new CompositePublicKey(null, null));
        }
        catch (InvalidKeyException e)
        {
            assertEquals("no matching key found", e.getMessage());
        }

        // single key test
        crl.verify(ecPub, BC);

        if (!crl.getIssuerX500Principal().equals(new X500Principal("CN=Test CA")))
        {
            fail("failed CRL issuer test");
        }

        byte[] authExt = crl.getExtensionValue(Extension.authorityKeyIdentifier.getId());

        if (authExt == null)
        {
            fail("failed to find CRL extension");
        }

        AuthorityKeyIdentifier authId = AuthorityKeyIdentifier.getInstance(ASN1OctetString.getInstance(authExt).getOctets());

        X509CRLEntry entry = crl.getRevokedCertificate(BigInteger.ONE);

        if (entry == null)
        {
            fail("failed to find CRL entry");
        }

        if (!entry.getSerialNumber().equals(BigInteger.ONE))
        {
            fail("CRL cert serial number does not match");
        }

        if (!entry.hasExtensions())
        {
            fail("CRL entry extension not found");
        }

        byte[] ext = entry.getExtensionValue(Extension.reasonCode.getId());

        if (ext != null)
        {
            ASN1Enumerated reasonCode = (ASN1Enumerated)fromExtensionValue(ext);

            if (!reasonCode.hasValue(CRLReason.privilegeWithdrawn))
            {
                fail("CRL entry reasonCode wrong");
            }
        }
        else
        {
            fail("CRL entry reasonCode not found");
        }

        sigGen = new JcaContentSignerBuilder("SHA256withECDSA", compAlgSpec).setProvider(BC).build(compPrivKey);

        crlHolder = crlGen.build(sigGen);

        crl = new JcaX509CRLConverter().setProvider(BC).getCRL(crlHolder);

        // comp test - single key
        crl.verify(compPub);
    }

    public void testDane()
        throws IOException, DANEException
    {
        final DANEEntryFactory daneEntryFactory = new DANEEntryFactory(new TruncatingDigestCalculator(new SHA256DigestCalculator()));

        DANEEntry entry = daneEntryFactory.createEntry("test@test.com", new X509CertificateHolder(DANETest.randomCert));

        if (!DANEEntry.isValidCertificate(entry.getRDATA()))
        {
            fail("encoding error in RDATA");
        }

        if (!"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15._smimecert.test.com".equals(entry.getDomainName()))
        {
            fail("domain name associated with entry wrong");
        }

        byte[] rdata = entry.getRDATA();
        byte[] certData = new byte[rdata.length - 3];

        System.arraycopy(rdata, 3, certData, 0, certData.length);

        if (!org.bouncycastle.util.Arrays.areEqual(certData, DANETest.randomCert))
        {
            fail("certificate encoding does not match");
        }

        DANEEntry entry2 = new DANEEntry("test@test.com", rdata);
        //assertEquals(entry, entry2);
        assertEquals(entry.getCertificate(), entry2.getCertificate());

        testException("unknown certificate usage: ", "DANEException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                daneEntryFactory.createEntry("test@test.com", 4, new X509CertificateHolder(DANETest.randomCert));
            }
        });
    }

    public void testPKCS10()
        throws Exception
    {
        int keySize = 512;
        String keyName = "RSA";
        String sigName = "SHA1withRSA";
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyName, "BC");

        kpg.initialize(keySize);

        KeyPair kp = kpg.genKeyPair();


        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE);

        x500NameBld.addRDN(BCStyle.C, "AU");
        x500NameBld.addRDN(BCStyle.O, "The Legion of the Bouncy Castle");
        x500NameBld.addRDN(BCStyle.L, "Melbourne");
        x500NameBld.addRDN(BCStyle.ST, "Victoria");
        x500NameBld.addRDN(BCStyle.EmailAddress, "feedback-crypto@bouncycastle.org");

        X500Name subject = x500NameBld.build();

        PKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(subject, kp.getPublic());

        PKCS10CertificationRequest req1 = requestBuilder.build(new JcaContentSignerBuilder(sigName).setProvider(new BouncyCastleProvider()).build(kp.getPrivate()));

        JcaPKCS10CertificationRequest req2 = new JcaPKCS10CertificationRequest(req1.toASN1Structure()).setProvider(new BouncyCastleProvider());

        if (!req2.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(new BouncyCastleProvider()).build(kp.getPublic())))
        {
            fail(sigName + ": Failed verify check.");
        }

        if (!org.bouncycastle.util.Arrays.areEqual(req2.getPublicKey().getEncoded(), req1.getSubjectPublicKeyInfo().getEncoded()))
        {
            fail(keyName + ": Failed public key check.");
        }
    }
}
