package org.bouncycastle.cert.test;

import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.openssl.MiscPEMGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;


public class Gost12Test extends SimpleTest {

    public String getName() {
        return "Gost12Test";
    }


    private final File data = new File("C:\\Users\\Mike\\Desktop\\ssl-test\\data.txt");
    private final File sign = new File("C:\\Users\\Mike\\Desktop\\ssl-test\\sign.sgn");
    private final File publicKey = new File("C:\\Users\\Mike\\Desktop\\ssl-test\\pub.pem");

    public void performTest() throws Exception{
//        alltest();

        signTest();

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

    public void alltest() throws Exception {
        try {


            ECKeyPairGenerator generator = new ECKeyPairGenerator();
            ECKeyGenerationParameters keyGenerationParameters = new ECKeyGenerationParameters(ECGOST3410NamedCurves.getByName("GostR3410-2001-CryptoPro-A"),
                    new SecureRandom());
            generator.init(keyGenerationParameters);
            AsymmetricCipherKeyPair asymmetricCipherKeyPair = generator.generateKeyPair();
            org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi keyFactory = new org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi.ECGOST3410();
            KeyPair caKeyPair = new KeyPair(keyFactory.generatePublic(SubjectPublicKeyInfoFactory.
                    createSubjectPublicKeyInfo(asymmetricCipherKeyPair.getPublic())),

                    keyFactory.generatePrivate(PrivateKeyInfoFactory.
                            createPrivateKeyInfo(asymmetricCipherKeyPair.getPrivate())));


            keyGenerationParameters = new ECKeyGenerationParameters(ECGOST3410NamedCurves.getByName("GostR3410-2001-CryptoPro-B"),
                    new SecureRandom());
            generator.init(keyGenerationParameters);
            asymmetricCipherKeyPair = generator.generateKeyPair();
            KeyPair keyPair = new KeyPair(keyFactory.generatePublic(SubjectPublicKeyInfoFactory.
                    createSubjectPublicKeyInfo(asymmetricCipherKeyPair.getPublic())),

                    keyFactory.generatePrivate(PrivateKeyInfoFactory.
                            createPrivateKeyInfo(asymmetricCipherKeyPair.getPrivate())));


            X509CertificateHolder holder;
            PKCS10CertificationRequest request;
            request = csrTest(keyPair, "GOST3411WITHECGOST3410");
//            String writeReq = convertToPem(request);
//            System.out.println(writeReq);
//            request = readPemRequest(writeReq);
            holder = certTest(request, "GOST3411WITHECGOST3410", caKeyPair.getPrivate());
//            String holderPem = convertToPem(holder);
//            System.out.println(holderPem);
//            holder = readPemCertificate(holderPem);


//            keyGenerationParameters = new ECKeyGenerationParameters(ECGOST3410NamedCurves.getByName("Tc26-Gost-3410-12-512-paramSetA"),
//                    new SecureRandom());
//            generator.init(keyGenerationParameters);
//            asymmetricCipherKeyPair = generator.generateKeyPair();
//            keyPair = new KeyPair(keyFactory.generatePublic(SubjectPublicKeyInfoFactory.
//                    createSubjectPublicKeyInfo(asymmetricCipherKeyPair.getPublic())),
//
//                    keyFactory.generatePrivate(PrivateKeyInfoFactory.
//                            createPrivateKeyInfo(asymmetricCipherKeyPair.getPrivate())));
//
//
//            request = csrTest(keyPair, "GOST3411WITHECGOST3410-2012-512");
//            writeReq = convertToPem(request);
//            System.out.println(writeReq);
//            request = readPemRequest(writeReq);
//            holder = certTest(request, "GOST3411WITHECGOST3410-2012-512", caKeyPair.getPrivate());
//            holderPem = convertToPem(holder);
//            System.out.println(holderPem);
//            holder = readPemCertificate(holderPem);


            writePem(new MiscPEMGenerator(holder), new File("holder.crt"));


        } catch (Exception ex) {
            ex.printStackTrace();
            throw ex;
        }
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

    private PKCS10CertificationRequest csrTest(KeyPair pair, String signatureAlgName) throws Exception {


        AsymmetricKeyParameter publicKey = PublicKeyFactory.createKey(pair.getPublic().getEncoded());

        AsymmetricKeyParameter privateKey = PrivateKeyFactory.createKey(pair.getPrivate().getEncoded());
        X500Name name = new X500Name("CN=AA, C=ou");
        PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(name,
                SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey));


        DefaultSignatureAlgorithmIdentifierFinder signatureAlgorithmIdentifierFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        DefaultDigestAlgorithmIdentifierFinder digestAlgorithmIdentifierFinder = new DefaultDigestAlgorithmIdentifierFinder();

        AlgorithmIdentifier signAlgId = signatureAlgorithmIdentifierFinder.find(signatureAlgName);
        AlgorithmIdentifier digestAlgId = digestAlgorithmIdentifierFinder.find(signAlgId);

        BcContentSignerBuilder signerBuilder = new BcECContentSignerBuilder(signAlgId, digestAlgId);

        PKCS10CertificationRequest request = builder.build(signerBuilder.build(privateKey));

        if (request == null) {
            fail("Cant build request for " + signatureAlgName);
        }

        return request;

    }

    private X509CertificateHolder certTest(PKCS10CertificationRequest request, String signatureAlgName, PrivateKey caPrivateKey) throws IOException, OperatorCreationException {

        X500Name name = new X500Name("CN=BB, C=aa");
        AsymmetricKeyParameter privateKey = PrivateKeyFactory.createKey(caPrivateKey.getEncoded());
        X509v3CertificateBuilder myCertificateGenerator = new X509v3CertificateBuilder(
                name,
                BigInteger.ONE,
                new Date(),
                new Date(new Date().getTime() + 364 * 50 * 3600),
                request.getSubject(),
                request.getSubjectPublicKeyInfo());

        DefaultSignatureAlgorithmIdentifierFinder signatureAlgorithmIdentifierFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        DefaultDigestAlgorithmIdentifierFinder digestAlgorithmIdentifierFinder = new DefaultDigestAlgorithmIdentifierFinder();

        AlgorithmIdentifier signAlgId = signatureAlgorithmIdentifierFinder.find(signatureAlgName);
        AlgorithmIdentifier digestAlgId = digestAlgorithmIdentifierFinder.find(signAlgId);

        BcContentSignerBuilder signerBuilder = new BcECContentSignerBuilder(signAlgId, digestAlgId);


        X509CertificateHolder holder = myCertificateGenerator.build(signerBuilder.build(privateKey));

        if (holder == null) {
            fail("Cant build request for " + signatureAlgName);
        }

        return holder;

    }




    private void signTest() throws Exception {
        try{
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keyGenerationParameters = new ECKeyGenerationParameters(ECGOST3410NamedCurves.getByName("Tc26-Gost-3410-12-512-paramSetA"),
                new SecureRandom());
        generator.init(keyGenerationParameters);
        AsymmetricCipherKeyPair asymmetricCipherKeyPair = generator.generateKeyPair();
        org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi keyFactory = new org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi.ECGOST3410();
        KeyPair caKeyPair = new KeyPair(keyFactory.generatePublic(SubjectPublicKeyInfoFactory.
                createSubjectPublicKeyInfo(asymmetricCipherKeyPair.getPublic())),

                keyFactory.generatePrivate(PrivateKeyInfoFactory.
                        createPrivateKeyInfo(asymmetricCipherKeyPair.getPrivate())));


        PrivateKey sKey = caKeyPair.getPrivate();
        PublicKey vKey = caKeyPair.getPublic();


        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(asymmetricCipherKeyPair.getPublic());


//        PemObject object = new PemObject(new MiscPEMGenerator(subjectPublicKeyInfo));
        writePem(new MiscPEMGenerator(subjectPublicKeyInfo), publicKey);


        Signature s = Signature.getInstance("ECGOST3410-2012-512", "BC");
        s.initSign(sKey);

        byte[] b = readAllBytes(data);
        s.update(b);

        byte [] sigBytes = s.sign();

        FileOutputStream fos = new FileOutputStream(sign);
        fos.write(sigBytes);
        fos.close();

        } catch (Exception ex) {
            ex.printStackTrace();
            throw ex;
        }


    }


    public static byte[] readAllBytes(File file) throws IOException {
        // Get the size of the file
        long length = file.length();

        // You cannot create an array using a long type.
        // It needs to be an int type.
        // Before converting to an int type, check
        // to ensure that file is not larger than Integer.MAX_VALUE.
        if (length > Integer.MAX_VALUE) {
            // File is too large
            throw new IOException("File is too large!");
        }

        // Create the byte array to hold the data
        byte[] bytes = new byte[(int)length];

        // Read in the bytes
        int offset = 0;
        int numRead = 0;

        InputStream is = new FileInputStream(file);
        try {
            while (offset < bytes.length
                    && (numRead=is.read(bytes, offset, bytes.length-offset)) >= 0) {
                offset += numRead;
            }
        } finally {
            is.close();
        }

        // Ensure all the bytes have been read in
        if (offset < bytes.length) {
            throw new IOException("Could not completely read file "+file.getName());
        }
        return bytes;
    }




    private String convertToPem(PKCS10CertificationRequest request) throws Exception {
        return writePem(new MiscPEMGenerator(request));
    }

    private String convertToPem(X509CertificateHolder holder) throws Exception {
        return writePem(new MiscPEMGenerator(holder));
    }

    private  X509CertificateHolder readPemCertificate(String pemString) throws Exception {
            return new X509CertificateHolder(readPem(pemString).getContent());

    }

    private  PKCS10CertificationRequest readPemRequest(String pemString) throws Exception {
        return new PKCS10CertificationRequest(readPem(pemString).getContent());

    }


    private  String writePem(PemObjectGenerator generator) throws Exception {
        StringWriter pemOut = new StringWriter();
        PemWriter pw = new PemWriter(pemOut);
        pw.writeObject(generator);
        pw.flush();

        return pemOut.toString();
    }

    private  void writePem(PemObjectGenerator generator, File file) throws Exception {
        FileWriter pemOut = new FileWriter(file);
        PemWriter pw = new PemWriter(pemOut);
        pw.writeObject(generator);
        pw.flush();
        pemOut.flush();
    }


    private  PemObject readPem(String pemString) throws Exception {
        StringReader stringReader = new StringReader(pemString);
        return readObject(stringReader);
    }


    private  PemObject readObject(Reader reader) throws Exception {

            PemReader pemReader = new PemReader(reader);
            PemObject object = pemReader.readPemObject();
            pemReader.close();
            return object;

    }




    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        Test test = new Gost12Test();
        TestResult result = test.perform();
        System.out.println(result);
    }
}
