package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V2TBSCertListGenerator;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;

public class CertPathBuilderTest
    extends SimpleTest
{

    private void baseTest()
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

            // initialise CertStore
        X509Certificate rootCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(CertPathTest.rootCertBin));
        X509Certificate interCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(CertPathTest.interCertBin));
        X509Certificate finalCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(CertPathTest.finalCertBin));
        X509CRL rootCrl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(CertPathTest.rootCrlBin));
        X509CRL interCrl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(CertPathTest.interCrlBin));
        List list = new ArrayList();
        list.add(rootCert);
        list.add(interCert);
        list.add(finalCert);
        list.add(rootCrl);
        list.add(interCrl);
        CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(list);
        CertStore store = CertStore.getInstance("Collection", ccsp, "BC");
        Date validDate = new Date(rootCrl.getThisUpdate().getTime() + 60 * 60 * 1000);

            //Searching for rootCert by subjectDN without CRL
        Set trust = new HashSet();
        trust.add(new TrustAnchor(rootCert, null));

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX","BC");
        X509CertSelector targetConstraints = new X509CertSelector();
        targetConstraints.setSubject(finalCert.getSubjectX500Principal().getEncoded());
        PKIXBuilderParameters params = new PKIXBuilderParameters(trust, targetConstraints);
        params.addCertStore(store);
        params.setDate(validDate);
        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) cpb.build(params);
        CertPath                  path = result.getCertPath();

        if (path.getCertificates().size() != 2)
        {
            fail("wrong number of certs in baseTest path");
        }
    }

    private void v0Test()
        throws Exception
    {
        // create certificates and CRLs
        KeyPair         rootPair = TestUtils.generateRSAKeyPair();
        KeyPair         interPair = TestUtils.generateRSAKeyPair();
        KeyPair         endPair = TestUtils.generateRSAKeyPair();

        X509Certificate rootCert = TestUtils.generateRootCert(rootPair);
        X509Certificate interCert = TestUtils.generateIntermediateCert(interPair.getPublic(), rootPair.getPrivate(), rootCert);
        X509Certificate endCert = TestUtils.generateEndEntityCert(endPair.getPublic(), interPair.getPrivate(), interCert);

        BigInteger revokedSerialNumber = BigInteger.valueOf(2);
        X509CRL         rootCRL = TestCertificateGen.createCRL(rootCert, rootPair.getPrivate(), revokedSerialNumber);
        X509CRL         interCRL = TestCertificateGen.createCRL(interCert, interPair.getPrivate(), revokedSerialNumber);

        // create CertStore to support path building
        List list = new ArrayList();

        list.add(rootCert);
        list.add(interCert);
        list.add(endCert);
        list.add(rootCRL);
        list.add(interCRL);

        CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
        CertStore                     store = CertStore.getInstance("Collection", params);

        // build the path
        CertPathBuilder  builder = CertPathBuilder.getInstance("PKIX", "BC");
        X509CertSelector pathConstraints = new X509CertSelector();

        pathConstraints.setSubject(endCert.getSubjectX500Principal().getEncoded());

        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(rootCert, null)), pathConstraints);

        buildParams.addCertStore(store);
        buildParams.setDate(new Date());

        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)builder.build(buildParams);
        CertPath                  path = result.getCertPath();

        if (path.getCertificates().size() != 2)
        {
            fail("wrong number of certs in v0Test path");
        }
    }

    private void noSigV0Test()
        throws Exception
    {
        // create certificates and CRLs
        KeyPair rootPair = TestUtils.generateRSAKeyPair();
        KeyPair interPair = TestUtils.generateRSAKeyPair();
        KeyPair endPair = TestUtils.generateRSAKeyPair();

        X509Certificate rootCert = TestUtils.generateNoSigRootCert(rootPair);
        X509Certificate interCert = TestUtils.generateIntermediateCert(interPair.getPublic(), rootPair.getPrivate(), rootCert);
        X509Certificate endCert = TestUtils.generateEndEntityCert(endPair.getPublic(), interPair.getPrivate(), interCert);

        BigInteger revokedSerialNumber = BigInteger.valueOf(2);
        X509CRL rootCRL = TestCertificateGen.createCRL(rootCert, rootPair.getPrivate(), revokedSerialNumber);
        X509CRL interCRL = TestCertificateGen.createCRL(interCert, interPair.getPrivate(), revokedSerialNumber);

        // create CertStore to support path building
        List list = new ArrayList();

        list.add(rootCert);
        list.add(interCert);
        list.add(endCert);
        list.add(rootCRL);
        list.add(interCRL);

        CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
        CertStore store = CertStore.getInstance("Collection", params);

        // build the path
        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
        X509CertSelector pathConstraints = new X509CertSelector();

        pathConstraints.setSubject(endCert.getSubjectX500Principal().getEncoded());

        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(rootCert, null)), pathConstraints);

        buildParams.addCertStore(store);
        buildParams.setDate(new Date());

        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)builder.build(buildParams);
        CertPath path = result.getCertPath();

        if (path.getCertificates().size() != 2)
        {
            fail("wrong number of certs in v0Test path");
        }
    }

    private void eeInSelectorTest()
        throws Exception
    {
        // create certificates and CRLs
        KeyPair         rootPair = TestUtils.generateRSAKeyPair();
        KeyPair         interPair = TestUtils.generateRSAKeyPair();
        KeyPair         endPair = TestUtils.generateRSAKeyPair();

        X509Certificate rootCert = TestUtils.generateRootCert(rootPair);
        X509Certificate interCert = TestUtils.generateIntermediateCert(interPair.getPublic(), rootPair.getPrivate(), rootCert);
        X509Certificate endCert = TestUtils.generateEndEntityCert(endPair.getPublic(), interPair.getPrivate(), interCert);

        // create CertStore to support path building
        List list = new ArrayList();

        list.add(interCert);
        list.add(endCert);
        
        CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
        CertStore                     store = CertStore.getInstance("Collection", params, "BC");

        // build the path
        CertPathBuilder  builder = CertPathBuilder.getInstance("PKIX", "BC");
        X509CertSelector pathConstraints = new X509CertSelector();

        pathConstraints.setCertificate(endCert);

        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(rootCert, null)), pathConstraints);

        buildParams.addCertStore(store);
        buildParams.setDate(new Date());
        buildParams.setRevocationEnabled(false);

        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)builder.build(buildParams);
        CertPath                  path = result.getCertPath();

        if (path.getCertificates().size() != 2)
        {
            fail("wrong number of certs in v0Test path");
        }
    }

    private void eeOnlyInSelectorTest()
        throws Exception
    {
        // create certificates and CRLs
        KeyPair         rootPair = TestUtils.generateRSAKeyPair();
        KeyPair         interPair = TestUtils.generateRSAKeyPair();
        KeyPair         endPair = TestUtils.generateRSAKeyPair();
        KeyPair         miscPair = TestUtils.generateRSAKeyPair();

        X509Certificate rootCert = TestUtils.generateRootCert(rootPair);
        X509Certificate interCert = TestUtils.generateIntermediateCert(interPair.getPublic(), rootPair.getPrivate(), rootCert);
        X509Certificate endCert = TestUtils.generateEndEntityCert(endPair.getPublic(), interPair.getPrivate(), interCert);
        X509Certificate miscCert = TestUtils.generateEndEntityCert(miscPair.getPublic(), interPair.getPrivate(), interCert);

        // create CertStore to support path building
        List list = new ArrayList();

        list.add(interCert);
        list.add(miscCert);

        CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
        CertStore                     store = CertStore.getInstance("Collection", params, "BC");

        // build the path
        CertPathBuilder  builder = CertPathBuilder.getInstance("PKIX", "BC");
        X509CertSelector pathConstraints = new X509CertSelector();

        pathConstraints.setCertificate(endCert);

        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(rootCert, null)), pathConstraints);

        buildParams.addCertStore(store);
        buildParams.setDate(new Date());
        buildParams.setRevocationEnabled(false);

        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)builder.build(buildParams);
        CertPath                  path = result.getCertPath();

        if (path.getCertificates().size() != 2)
        {
            fail("wrong number of certs in v0Test path");
        }
    }

    private void multipleTrustAnchorsWithCRLTest()
        throws Exception
    {
        // github #2291: with CRL revocation enabled and multiple trust anchors whose
        // subjects match the CRL issuer name, the previous code recursed into a fresh
        // CertPathBuilder build for every candidate signer, and that recursive build
        // re-entered CRL processing on the same CRL. The fix short-circuits when the
        // candidate signer is itself a trust anchor.
        KeyPair rootPair = TestUtils.generateRSAKeyPair();
        KeyPair otherRootPair = TestUtils.generateRSAKeyPair();
        KeyPair interPair = TestUtils.generateRSAKeyPair();
        KeyPair endPair = TestUtils.generateRSAKeyPair();

        org.bouncycastle.asn1.x500.X500Name rootDN =
            new org.bouncycastle.asn1.x500.X500Name("CN=Test CA Certificate");

        // Two self-signed roots sharing the same Subject DN — different keys.
        X509Certificate rootCert = TestUtils.generateRootCert(rootPair, rootDN);
        X509Certificate otherRootCert = TestUtils.generateRootCert(otherRootPair, rootDN);

        X509Certificate interCert = TestUtils.generateIntermediateCert(
            interPair.getPublic(), rootPair.getPrivate(), rootCert);
        X509Certificate endCert = TestUtils.generateEndEntityCert(
            endPair.getPublic(), interPair.getPrivate(), interCert);

        BigInteger revokedSerial = BigInteger.valueOf(2);
        X509CRL rootCRL = TestCertificateGen.createCRL(rootCert, rootPair.getPrivate(), revokedSerial);
        X509CRL interCRL = TestCertificateGen.createCRL(interCert, interPair.getPrivate(), revokedSerial);

        List collection = new ArrayList();
        collection.add(rootCert);
        collection.add(otherRootCert);
        collection.add(interCert);
        collection.add(endCert);
        collection.add(rootCRL);
        collection.add(interCRL);
        CertStore store = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(collection), "BC");

        Set anchors = new HashSet();
        anchors.add(new TrustAnchor(rootCert, null));
        anchors.add(new TrustAnchor(otherRootCert, null));

        X509CertSelector pathConstraints = new X509CertSelector();
        pathConstraints.setSubject(endCert.getSubjectX500Principal().getEncoded());

        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(anchors, pathConstraints);
        buildParams.addCertStore(store);
        buildParams.setDate(new Date());
        buildParams.setRevocationEnabled(true);

        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)builder.build(buildParams);
        CertPath path = result.getCertPath();

        if (path.getCertificates().size() != 2)
        {
            fail("wrong number of certs in multi-anchor path: " + path.getCertificates().size());
        }
    }

    public void performTest()
        throws Exception
    {
        baseTest();
        v0Test();
        noSigV0Test();
        eeInSelectorTest();
        eeOnlyInSelectorTest();
        multipleTrustAnchorsWithCRLTest();
        manyTrustAnchorsAkiNarrowingPerfTest();
    }

    private static final String SHA256_RSA = "SHA256withRSA";

    /**
     * github #2291 follow-up: with the recursion guard alone, runtime grows
     * O(N^depth) when N trust anchors share the issuer DN — every CRL check
     * fans out across all candidate signers. RFC3280CertPathUtilities.processCRLF
     * narrows the candidate set by the CRL's authorityKeyIdentifier (RFC 5280
     * sec. 5.2.1) when present. With six roots sharing a Subject DN this test
     * completes in milliseconds; without the AKI narrowing it took several
     * minutes (see charlesvdv's benchmark on the issue).
     */
    private void manyTrustAnchorsAkiNarrowingPerfTest()
        throws Exception
    {
        // Real signer + 5 decoy roots, all sharing the same Subject DN, each
        // with a distinct key (so each cert ends up with a distinct SKI).
        final int decoyCount = 5;
        X500Name rootDN = new X500Name("CN=Test CA Certificate");

        KeyPair realRootPair = TestUtils.generateRSAKeyPair();
        byte[] realRootSki = computeSki(realRootPair.getPublic());
        X509Certificate realRootCert = selfSignedV3CaCert(realRootPair, rootDN, realRootSki);

        List trustCerts = new ArrayList();
        trustCerts.add(realRootCert);
        for (int i = 0; i < decoyCount; i++)
        {
            KeyPair decoyPair = TestUtils.generateRSAKeyPair();
            byte[] decoySki = computeSki(decoyPair.getPublic());
            trustCerts.add(selfSignedV3CaCert(decoyPair, rootDN, decoySki));
        }

        KeyPair interPair = TestUtils.generateRSAKeyPair();
        byte[] interSki = computeSki(interPair.getPublic());
        X509Certificate interCert = subordinateV3Cert(
            new X500Name("CN=Test Intermediate Certificate"),
            interPair.getPublic(), interSki,
            realRootPair.getPrivate(), rootDN, realRootSki,
            true);

        KeyPair endPair = TestUtils.generateRSAKeyPair();
        X509Certificate endCert = subordinateV3Cert(
            new X500Name("CN=Test End Certificate"),
            endPair.getPublic(), computeSki(endPair.getPublic()),
            interPair.getPrivate(), new X500Name("CN=Test Intermediate Certificate"), interSki,
            false);

        BigInteger revokedSerial = BigInteger.valueOf(99999);
        // CRL signed by the real root, AKI keyIdentifier = real root's SKI.
        X509CRL rootCRL = crlWithKeyIdAki(realRootCert, realRootPair.getPrivate(), revokedSerial, realRootSki);
        // CRL signed by intermediate, AKI keyIdentifier = intermediate's SKI.
        X509CRL interCRL = crlWithKeyIdAki(interCert, interPair.getPrivate(), revokedSerial, interSki);

        List collection = new ArrayList();
        collection.addAll(trustCerts);
        collection.add(interCert);
        collection.add(endCert);
        collection.add(rootCRL);
        collection.add(interCRL);
        CertStore store = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(collection), "BC");

        Set anchors = new HashSet();
        for (int i = 0; i < trustCerts.size(); i++)
        {
            anchors.add(new TrustAnchor((X509Certificate)trustCerts.get(i), null));
        }

        X509CertSelector pathConstraints = new X509CertSelector();
        pathConstraints.setSubject(endCert.getSubjectX500Principal().getEncoded());

        final PKIXBuilderParameters buildParams = new PKIXBuilderParameters(anchors, pathConstraints);
        buildParams.addCertStore(store);
        buildParams.setDate(new Date());
        buildParams.setRevocationEnabled(true);

        // Run the build with a hard wall-time bound. Pre-fix wall time for
        // N=6 roots is multiple minutes (see issue benchmark). Post-fix it
        // should complete in well under a second. Use a daemon thread so the
        // pre-fix runaway recursion doesn't keep the JVM alive after we
        // declare the test failed.
        ExecutorService exec = Executors.newSingleThreadExecutor(new ThreadFactory()
        {
            public Thread newThread(Runnable r)
            {
                Thread t = new Thread(r, "CertPathBuilderTest-perf");
                t.setDaemon(true);
                return t;
            }
        });
        try
        {
            Future fut = exec.submit(new Callable()
            {
                public Object call()
                    throws Exception
                {
                    CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
                    return (PKIXCertPathBuilderResult)builder.build(buildParams);
                }
            });

            long startMs = System.currentTimeMillis();
            PKIXCertPathBuilderResult result;
            try
            {
                result = (PKIXCertPathBuilderResult)fut.get(30, TimeUnit.SECONDS);
            }
            catch (TimeoutException e)
            {
                fut.cancel(true);
                fail("CertPath build with " + trustCerts.size()
                    + " trust anchors sharing the issuer DN exceeded 30s — AKI narrowing in processCRLF appears to be missing");
                return;
            }
            catch (ExecutionException e)
            {
                if (e.getCause() instanceof Exception)
                {
                    throw (Exception)e.getCause();
                }
                throw e;
            }

            long elapsedMs = System.currentTimeMillis() - startMs;

            CertPath path = result.getCertPath();
            if (path.getCertificates().size() != 2)
            {
                fail("wrong number of certs in AKI-narrowing perf path: " + path.getCertificates().size());
            }
            // Sanity: with the fix, this typically completes in tens or
            // hundreds of milliseconds. A several-second result would suggest
            // the AKI narrowing isn't taking effect for some reason.
            if (elapsedMs > 5000L)
            {
                fail("CertPath build with " + trustCerts.size()
                    + " trust anchors took " + elapsedMs + " ms (expected sub-second)");
            }
        }
        finally
        {
            exec.shutdownNow();
        }
    }

    private static X509Certificate selfSignedV3CaCert(KeyPair pair, X500Name dn, byte[] ski)
        throws Exception
    {
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        extGen.addExtension(Extension.keyUsage, true,
            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));
        extGen.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(ski));
        return signV3Cert(dn, pair.getPrivate(), dn, pair.getPublic(), extGen);
    }

    private static X509Certificate subordinateV3Cert(
        X500Name subjectDN,
        PublicKey subjectKey, byte[] subjectSki,
        PrivateKey issuerKey, X500Name issuerDN, byte[] issuerSki,
        boolean isCa)
        throws Exception
    {
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.basicConstraints, true, isCa ? new BasicConstraints(0) : new BasicConstraints(false));
        int ku = isCa
            ? (KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign)
            : KeyUsage.digitalSignature;
        extGen.addExtension(Extension.keyUsage, true, new KeyUsage(ku));
        extGen.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(subjectSki));
        extGen.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(issuerSki));
        return signV3Cert(subjectDN, issuerKey, issuerDN, subjectKey, extGen);
    }

    private static X509Certificate signV3Cert(
        X500Name subjectDN, PrivateKey issuerKey, X500Name issuerDN,
        PublicKey subjectKey, ExtensionsGenerator extGen)
        throws Exception
    {
        V3TBSCertificateGenerator g = new V3TBSCertificateGenerator();
        long now = System.currentTimeMillis();
        g.setSerialNumber(ASN1Integer.valueOf(TestUtils.nextSerialNumber()));
        g.setIssuer(issuerDN);
        g.setSubject(subjectDN);
        g.setStartDate(new Time(new Date(now - 5000)));
        g.setEndDate(new Time(new Date(now + 30 * 60 * 1000)));
        g.setSignature(rsaSha256AlgId());
        g.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(subjectKey.getEncoded()));
        g.setExtensions(extGen.generate());

        TBSCertificate tbs = g.generateTBSCertificate();
        Signature sig = Signature.getInstance(SHA256_RSA, "BC");
        sig.initSign(issuerKey);
        sig.update(tbs.getEncoded(ASN1Encoding.DER));

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbs);
        v.add(rsaSha256AlgId());
        v.add(new DERBitString(sig.sign()));

        return (X509Certificate)CertificateFactory.getInstance("X.509", "BC")
            .generateCertificate(new ByteArrayInputStream(new DERSequence(v).getEncoded(ASN1Encoding.DER)));
    }

    private static X509CRL crlWithKeyIdAki(
        X509Certificate caCert, PrivateKey caKey,
        BigInteger revokedSerial, byte[] caSki)
        throws Exception
    {
        V2TBSCertListGenerator g = new V2TBSCertListGenerator();
        Date now = new Date();
        X500Name issuer = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());
        g.setIssuer(issuer);
        g.setThisUpdate(new Time(now));
        g.setNextUpdate(new Time(new Date(now.getTime() + 100000)));
        g.setSignature(rsaSha256AlgId());
        g.addCRLEntry(new ASN1Integer(revokedSerial), new Time(now), CRLReason.privilegeWithdrawn);

        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(caSki));
        extGen.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(1)));
        g.setExtensions(extGen.generate());

        TBSCertList tbs = g.generateTBSCertList();
        Signature sig = Signature.getInstance(SHA256_RSA, "BC");
        sig.initSign(caKey);
        sig.update(tbs.getEncoded(ASN1Encoding.DER));

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbs);
        v.add(rsaSha256AlgId());
        v.add(new DERBitString(sig.sign()));

        return (X509CRL)CertificateFactory.getInstance("X.509", "BC")
            .generateCRL(new ByteArrayInputStream(new DERSequence(v).getEncoded(ASN1Encoding.DER)));
    }

    private static AlgorithmIdentifier rsaSha256AlgId()
    {
        return new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption,
            org.bouncycastle.asn1.DERNull.INSTANCE);
    }

    private static byte[] computeSki(PublicKey pubKey)
    {
        // RFC 5280 sec. 4.2.1.2 method (1): SHA-1 of the BIT STRING value of
        // SubjectPublicKey (excluding tag, length, unused-bits prefix).
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(pubKey.getEncoded());
        byte[] keyBytes = spki.getPublicKeyData().getBytes();
        SHA1Digest digest = new SHA1Digest();
        digest.update(keyBytes, 0, keyBytes.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }
    
    public String getName()
    {
        return "CertPathBuilder";
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new CertPathBuilderTest());
    }
}

