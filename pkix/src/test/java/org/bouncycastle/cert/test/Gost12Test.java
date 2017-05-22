package org.bouncycastle.cert.test;

import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyFactorySpi;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.MiscPEMGenerator;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
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
import java.util.Date;


public class Gost12Test extends SimpleTest {

    public String getName() {
        return "Gost12Test";
    }


    private final File data = new File("C:\\Users\\Mike\\Desktop\\ssl-test\\data.txt");
    private final File sign = new File("C:\\Users\\Mike\\Desktop\\ssl-test\\sign.sgn");
    private final File publicKey = new File("C:\\Users\\Mike\\Desktop\\ssl-test\\pub.pem");

    public void performTest() throws Exception{
        alltest();

//        signTest();
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
