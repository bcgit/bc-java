package org.bouncycastle.cert.test;

import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;


public class GOST3410_2012CMSTest extends SimpleTest {

    public String getName() {
        return "GOST3410 2012 CMS TEST";
    }

    public void performTest() throws Exception{

        cmsTest("GOST-3410-2012", "Tc26-Gost-3410-12-512-paramSetA", "GOST3411-2012-512WITHECGOST3410-2012-512",
                RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512.getId());
        cmsTest("GOST-3410-2012", "Tc26-Gost-3410-12-512-paramSetB", "GOST3411-2012-512WITHECGOST3410-2012-512",
                RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512.getId());
        cmsTest("GOST-3410-2012", "Tc26-Gost-3410-12-512-paramSetC", "GOST3411-2012-512WITHECGOST3410-2012-512",
                RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512.getId());
        cmsTest("GOST-3410-2012", "Tc26-Gost-3410-12-256-paramSetA", "GOST3411-2012-256WITHECGOST3410-2012-256",
                RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256.getId());
    }

    public void cmsTest(String keyAlgorithm, String paramName, String signAlgorithm, String digestId){
        try {
            KeyPairGenerator keyPairGenerator =
                    KeyPairGenerator.getInstance(keyAlgorithm, "BC");
            keyPairGenerator.initialize(new ECNamedCurveGenParameterSpec(paramName), new SecureRandom());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            X509CertificateHolder signingCertificate = selfSignedCertificate(keyPair, signAlgorithm);

            // CMS
            byte[] dataContent = new byte[]{1, 2, 3, 4, 33, 22, 11, 33, 52, 21, 23};
            CMSTypedData cmsTypedData = new CMSProcessableByteArray(dataContent);


            final JcaSignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(
                    new JcaDigestCalculatorProviderBuilder().setProvider("BC").build());

            final ContentSigner contentSigner = new
                    JcaContentSignerBuilder(signAlgorithm).setProvider("BC")
                    .build(keyPair.getPrivate());

            final SignerInfoGenerator signerInfoGenerator = signerInfoGeneratorBuilder.build(contentSigner, signingCertificate);

            CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();

            cmsSignedDataGenerator.addCertificate(signingCertificate);
            cmsSignedDataGenerator.addSignerInfoGenerator(signerInfoGenerator);

            CMSSignedData cmsSignedData = cmsSignedDataGenerator.generate(cmsTypedData, false);
            if(cmsSignedData == null){
                fail("Cant create CMS");
            }

            boolean algIdContains = false;
            for(AlgorithmIdentifier algorithmIdentifier : cmsSignedData.getDigestAlgorithmIDs()){
                if(algorithmIdentifier.getAlgorithm().getId().equals(digestId)){
                    algIdContains = true;
                    break;
                }
            }
            if(!algIdContains){
                fail("identifier not valid");
            }
            boolean result = verify(cmsSignedData, cmsTypedData);
            if(!result){
                fail("Verification fails ");
            }

        }
        catch (Exception ex){
            ex.printStackTrace();
            fail("fail with exception:", ex);
        }
    }

    private boolean verify(CMSSignedData signature, CMSTypedData typedData) throws CertificateException, OperatorCreationException, IOException, CMSException {
        CMSSignedData signedDataToVerify = new CMSSignedData(typedData, signature.getEncoded());
        Store certs = signedDataToVerify.getCertificates();
        SignerInformationStore signers = signedDataToVerify.getSignerInfos();
        Collection<SignerInformation> c = signers.getSigners();
        for (SignerInformation signer : c) {
            SignerId signerId = signer.getSID();
            Collection certCollection = certs.getMatches(signerId);

            Iterator certIt = certCollection.iterator();
            Object certificate = certIt.next();
            SignerInformationVerifier verifier =
                    new JcaSimpleSignerInfoVerifierBuilder()
                            .setProvider("BC").build((X509CertificateHolder)certificate);


            boolean result =  signer.verify(verifier);
            if (result) {
                return true;
            }
        }
        return false;
    }

    private X509CertificateHolder selfSignedCertificate(KeyPair keyPair, String signatureAlgName) throws IOException, OperatorCreationException {

        X500Name name = new X500Name("CN=BB, C=aa");
        ECPublicKey k = (ECPublicKey)keyPair.getPublic();
        ECParameterSpec s = k.getParameters();
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(
                k.getQ(),
                new ECDomainParameters(s.getCurve(), s.getG(), s.getN()));

        ECPrivateKey kk = (ECPrivateKey)keyPair.getPrivate();
        ECParameterSpec ss = kk.getParameters();

        ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(
                kk.getD(),
                new ECDomainParameters(ss.getCurve(), ss.getG(), ss.getN()));

        AsymmetricKeyParameter publicKey = ecPublicKeyParameters;
        AsymmetricKeyParameter privateKey = ecPrivateKeyParameters;
        X509v3CertificateBuilder myCertificateGenerator = new X509v3CertificateBuilder(
                name,
                BigInteger.ONE,
                new Date(),
                new Date(new Date().getTime() + 364 * 50 * 3600),
                name,
                SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey));

        DefaultSignatureAlgorithmIdentifierFinder signatureAlgorithmIdentifierFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        DefaultDigestAlgorithmIdentifierFinder digestAlgorithmIdentifierFinder = new DefaultDigestAlgorithmIdentifierFinder();

        AlgorithmIdentifier signAlgId = signatureAlgorithmIdentifierFinder.find(signatureAlgName);
        AlgorithmIdentifier digestAlgId = digestAlgorithmIdentifierFinder.find(signAlgId);

        BcContentSignerBuilder signerBuilder = new BcECContentSignerBuilder(signAlgId, digestAlgId);

        int val = KeyUsage.cRLSign;
        val = val | KeyUsage.dataEncipherment;
        val = val | KeyUsage.decipherOnly;
        val = val | KeyUsage.digitalSignature;
        val = val | KeyUsage.encipherOnly;
        val = val | KeyUsage.keyAgreement;
        val = val | KeyUsage.keyEncipherment;
        val = val | KeyUsage.nonRepudiation;
        myCertificateGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(val)  );

        myCertificateGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        myCertificateGenerator.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));




        X509CertificateHolder holder = myCertificateGenerator.build(signerBuilder.build(privateKey));

        return holder;
    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        Test test = new GOST3410_2012CMSTest();
        TestResult result = test.perform();
        System.out.println(result);
    }
}
