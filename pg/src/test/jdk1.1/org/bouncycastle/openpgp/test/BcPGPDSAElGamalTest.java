package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.UncloseableOutputStream;

public class BcPGPDSAElGamalTest
    extends SimpleTest
{

    byte[] testPubKeyRing =
        Base64.decode(
            "mQGiBEAR8jYRBADNifuSopd20JOQ5x30ljIaY0M6927+vo09NeNxS3KqItba"
         + "nz9o5e2aqdT0W1xgdHYZmdElOHTTsugZxdXTEhghyxoo3KhVcNnTABQyrrvX"
         + "qouvmP2fEDEw0Vpyk+90BpyY9YlgeX/dEA8OfooRLCJde/iDTl7r9FT+mts8"
         + "g3azjwCgx+pOLD9LPBF5E4FhUOdXISJ0f4EEAKXSOi9nZzajpdhe8W2ZL9gc"
         + "BpzZi6AcrRZBHOEMqd69gtUxA4eD8xycUQ42yH89imEcwLz8XdJ98uHUxGJi"
         + "qp6hq4oakmw8GQfiL7yQIFgaM0dOAI9Afe3m84cEYZsoAFYpB4/s9pVMpPRH"
         + "NsVspU0qd3NHnSZ0QXs8L8DXGO1uBACjDUj+8GsfDCIP2QF3JC+nPUNa0Y5t"
         + "wKPKl+T8hX/0FBD7fnNeC6c9j5Ir/Fp/QtdaDAOoBKiyNLh1JaB1NY6US5zc"
         + "qFks2seZPjXEiE6OIDXYra494mjNKGUobA4hqT2peKWXt/uBcuL1mjKOy8Qf"
         + "JxgEd0MOcGJO+1PFFZWGzLQ3RXJpYyBILiBFY2hpZG5hICh0ZXN0IGtleSBv"
         + "bmx5KSA8ZXJpY0Bib3VuY3ljYXN0bGUub3JnPohZBBMRAgAZBQJAEfI2BAsH"
         + "AwIDFQIDAxYCAQIeAQIXgAAKCRAOtk6iUOgnkDdnAKC/CfLWikSBdbngY6OK"
         + "5UN3+o7q1ACcDRqjT3yjBU3WmRUNlxBg3tSuljmwAgAAuQENBEAR8jgQBAC2"
         + "kr57iuOaV7Ga1xcU14MNbKcA0PVembRCjcVjei/3yVfT/fuCVtGHOmYLEBqH"
         + "bn5aaJ0P/6vMbLCHKuN61NZlts+LEctfwoya43RtcubqMc7eKw4k0JnnoYgB"
         + "ocLXOtloCb7jfubOsnfORvrUkK0+Ne6anRhFBYfaBmGU75cQgwADBQP/XxR2"
         + "qGHiwn+0YiMioRDRiIAxp6UiC/JQIri2AKSqAi0zeAMdrRsBN7kyzYVVpWwN"
         + "5u13gPdQ2HnJ7d4wLWAuizUdKIQxBG8VoCxkbipnwh2RR4xCXFDhJrJFQUm+"
         + "4nKx9JvAmZTBIlI5Wsi5qxst/9p5MgP3flXsNi1tRbTmRhqIRgQYEQIABgUC"
         + "QBHyOAAKCRAOtk6iUOgnkBStAJoCZBVM61B1LG2xip294MZecMtCwQCbBbsk"
         + "JVCXP0/Szm05GB+WN+MOCT2wAgAA");
           
    byte[] testPrivKeyRing =
        Base64.decode(
            "lQHhBEAR8jYRBADNifuSopd20JOQ5x30ljIaY0M6927+vo09NeNxS3KqItba"
         + "nz9o5e2aqdT0W1xgdHYZmdElOHTTsugZxdXTEhghyxoo3KhVcNnTABQyrrvX"
         + "qouvmP2fEDEw0Vpyk+90BpyY9YlgeX/dEA8OfooRLCJde/iDTl7r9FT+mts8"
         + "g3azjwCgx+pOLD9LPBF5E4FhUOdXISJ0f4EEAKXSOi9nZzajpdhe8W2ZL9gc"
         + "BpzZi6AcrRZBHOEMqd69gtUxA4eD8xycUQ42yH89imEcwLz8XdJ98uHUxGJi"
         + "qp6hq4oakmw8GQfiL7yQIFgaM0dOAI9Afe3m84cEYZsoAFYpB4/s9pVMpPRH"
         + "NsVspU0qd3NHnSZ0QXs8L8DXGO1uBACjDUj+8GsfDCIP2QF3JC+nPUNa0Y5t"
         + "wKPKl+T8hX/0FBD7fnNeC6c9j5Ir/Fp/QtdaDAOoBKiyNLh1JaB1NY6US5zc"
         + "qFks2seZPjXEiE6OIDXYra494mjNKGUobA4hqT2peKWXt/uBcuL1mjKOy8Qf"
         + "JxgEd0MOcGJO+1PFFZWGzP4DAwLeUcsVxIC2s2Bb9ab2XD860TQ2BI2rMD/r"
         + "7/psx9WQ+Vz/aFAT3rXkEJ97nFeqEACgKmUCAEk9939EwLQ3RXJpYyBILiBF"
         + "Y2hpZG5hICh0ZXN0IGtleSBvbmx5KSA8ZXJpY0Bib3VuY3ljYXN0bGUub3Jn"
         + "PohZBBMRAgAZBQJAEfI2BAsHAwIDFQIDAxYCAQIeAQIXgAAKCRAOtk6iUOgn"
         + "kDdnAJ9Ala3OcwEV1DbK906CheYWo4zIQwCfUqUOLMp/zj6QAk02bbJAhV1r"
         + "sAewAgAAnQFYBEAR8jgQBAC2kr57iuOaV7Ga1xcU14MNbKcA0PVembRCjcVj"
         + "ei/3yVfT/fuCVtGHOmYLEBqHbn5aaJ0P/6vMbLCHKuN61NZlts+LEctfwoya"
         + "43RtcubqMc7eKw4k0JnnoYgBocLXOtloCb7jfubOsnfORvrUkK0+Ne6anRhF"
         + "BYfaBmGU75cQgwADBQP/XxR2qGHiwn+0YiMioRDRiIAxp6UiC/JQIri2AKSq"
         + "Ai0zeAMdrRsBN7kyzYVVpWwN5u13gPdQ2HnJ7d4wLWAuizUdKIQxBG8VoCxk"
         + "bipnwh2RR4xCXFDhJrJFQUm+4nKx9JvAmZTBIlI5Wsi5qxst/9p5MgP3flXs"
         + "Ni1tRbTmRhr+AwMC3lHLFcSAtrNg/EiWFLAnKNXH27zjwuhje8u2r+9iMTYs"
         + "GjbRxaxRY0GKRhttCwqe2BC0lHhzifdlEcc9yjIjuKfepG2fnnSIRgQYEQIA"
         + "BgUCQBHyOAAKCRAOtk6iUOgnkBStAJ9HFejVtVJ/A9LM/mDPe0ExhEXt/QCg"
         + "m/KM7hJ/JrfnLQl7IaZsdg1F6vCwAgAA");

    byte[] encMessage =
        Base64.decode(
            "hQEOAynbo4lhNjcHEAP/dgCkMtPB6mIgjFvNiotjaoh4sAXf4vFNkSeehQ2c"
         + "r+IMt9CgIYodJI3FoJXxOuTcwesqTp5hRzgUBJS0adLDJwcNubFMy0M2tp5o"
         + "KTWpXulIiqyO6f5jI/oEDHPzFoYgBmR4x72l/YpMy8UoYGtNxNvR7LVOfqJv"
         + "uDY/71KMtPQEAIadOWpf1P5Td+61Zqn2VH2UV7H8eI6hGa6Lsy4sb9iZNE7f"
         + "c+spGJlgkiOt8TrQoq3iOK9UN9nHZLiCSIEGCzsEn3uNuorD++Qs065ij+Oy"
         + "36TKeuJ+38CfT7u47dEshHCPqWhBKEYrxZWHUJU/izw2Q1Yxd2XRxN+nafTL"
         + "X1fQ0lABQUASa18s0BkkEERIdcKQXVLEswWcGqWNv1ZghC7xO2VDBX4HrPjp"
         + "drjL63p2UHzJ7/4gPWGGtnqq1Xita/1mrImn7pzLThDWiT55vjw6Hw==");

    byte[] signedAndEncMessage =
        Base64.decode(
            "hQEOAynbo4lhNjcHEAP+K20MVhzdX57hf/cU8TH0prP0VePr9mmeBedzqqMn"
         + "fp2p8Zb68zmcMlI/WiL5XMNLYRmCgEcXyWbKdP/XV9m9LDBe1CMAGrkCeGBy"
         + "je69IQQ5LS9vDPyEMF4iAAv/EqACjqHkizdY/a/FRx/t2ioXYdEC2jA6kS9C"
         + "McpsNz16DE8EAIk3uKn4bGo/+15TXkyFYzW5Cf71SfRoHNmU2zAI93zhjN+T"
         + "B7mGJwWXzsMkIO6FkMU5TCSrwZS3DBWCIaJ6SYoaawE/C/2j9D7bX1Jv8kum"
         + "4cq+eZM7z6JYs6xend+WAwittpUxbEiyC2AJb3fBSXPAbLqWd6J6xbZZ7GDK"
         + "r2Ca0pwBxwGhbMDyi2zpHLzw95H7Ah2wMcGU6kMLB+hzBSZ6mSTGFehqFQE3"
         + "2BnAj7MtnbghiefogacJ891jj8Y2ggJeKDuRz8j2iICaTOy+Y2rXnnJwfYzm"
         + "BMWcd2h1C5+UeBJ9CrrLniCCI8s5u8z36Rno3sfhBnXdRmWSxExXtocbg1Ht"
         + "dyiThf6TK3W29Yy/T6x45Ws5zOasaJdsFKM=");    
    char[] pass = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd' };
    
    public void performTest()
        throws Exception
    {
        try
        {
            PGPPublicKey pubKey;

            //
            // Read the public key
            //
            JcaPGPObjectFactory    pgpFact = new JcaPGPObjectFactory(testPubKeyRing);
            
            PGPPublicKeyRing        pgpPub = (PGPPublicKeyRing)pgpFact.nextObject();

               pubKey = pgpPub.getPublicKey();

            if (pubKey.getBitStrength() != 1024)
            {
                fail("failed - key strength reported incorrectly.");
            }

            //
            // Read the private key
            //
            PGPSecretKeyRing    sKey = new PGPSecretKeyRing(testPrivKeyRing, new BcKeyFingerprintCalculator());
            PGPPrivateKey        pgpPrivKey = sKey.getSecretKey().extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(pass));
            
            //
            // signature generation
            //
            String                                data = "hello world!";
            ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
            ByteArrayInputStream        testIn = new ByteArrayInputStream(data.getBytes());
            PGPSignatureGenerator    sGen = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(PGPPublicKey.DSA, PGPUtil.SHA1));
        
            sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

            PGPCompressedDataGenerator cGen = new PGPCompressedDataGenerator(
                PGPCompressedData.ZIP);

            BCPGOutputStream bcOut = new BCPGOutputStream(
                cGen.open(new UncloseableOutputStream(bOut)));

            sGen.generateOnePassVersion(false).encode(bcOut);

            PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
            
            Date testDate = new Date((System.currentTimeMillis() / 1000) * 1000);
            OutputStream lOut = lGen.open(
                new UncloseableOutputStream(bcOut),
                PGPLiteralData.BINARY,
                "_CONSOLE",
                data.getBytes().length,
                testDate);

            int ch;
            while ((ch = testIn.read()) >= 0)
            {
                lOut.write(ch);
                sGen.update((byte)ch);
            }

            lGen.close();

            sGen.generate().encode(bcOut);

            cGen.close();

            //
            // verify generated signature
            //
            pgpFact = new JcaPGPObjectFactory(bOut.toByteArray());

            PGPCompressedData c1 = (PGPCompressedData)pgpFact.nextObject();

            pgpFact = new JcaPGPObjectFactory(c1.getDataStream());
            
            PGPOnePassSignatureList p1 = (PGPOnePassSignatureList)pgpFact.nextObject();
            
            PGPOnePassSignature ops = p1.get(0);
            
            PGPLiteralData p2 = (PGPLiteralData)pgpFact.nextObject();
            if (!p2.getModificationTime().equals(testDate))
            {
                fail("Modification time not preserved");
            }

            InputStream    dIn = p2.getInputStream();

            ops.init(new BcPGPContentVerifierBuilderProvider(), pubKey);
            
            while ((ch = dIn.read()) >= 0)
            {
                ops.update((byte)ch);
            }

            PGPSignatureList p3 = (PGPSignatureList)pgpFact.nextObject();

            if (!ops.verify(p3.get(0)))
            {
                fail("Failed generated signature check");
            }
            
            //
            // test encryption
            //
            
            //
            // find a key suitable for encryption
            //
            long            pgpKeyID = 0;
            AsymmetricKeyParameter pKey = null;
            BcPGPKeyConverter keyConverter = new BcPGPKeyConverter();

            Iterator    it = pgpPub.getPublicKeys();
            while (it.hasNext())
            {
                PGPPublicKey    pgpKey = (PGPPublicKey)it.next();

                if (pgpKey.getAlgorithm() == PGPPublicKey.ELGAMAL_ENCRYPT
                    || pgpKey.getAlgorithm() == PGPPublicKey.ELGAMAL_GENERAL)
                {
                    pKey = keyConverter.getPublicKey(pgpKey);
                    pgpKeyID = pgpKey.getKeyID();
                    if (pgpKey.getBitStrength() != 1024)
                    {
                        fail("failed - key strength reported incorrectly.");
                    }
                    
                    //
                    // verify the key
                    //
                    
                }
            }
             
            AsymmetricBlockCipher c = new PKCS1Encoding(new ElGamalEngine());

            c.init(true, pKey);
            
            byte[]  in = "hello world".getBytes();

            byte[]  out = c.processBlock(in, 0, in.length);
            
            pgpPrivKey = sKey.getSecretKey(pgpKeyID).extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(pass));
            
            c.init(false, keyConverter.getPrivateKey(pgpPrivKey));
            
            out = c.processBlock(out, 0, out.length);
            
            if (!areEqual(in, out))
            {
                fail("decryption failed.");
            }

            //
            // encrypted message
            //
            byte[]    text = { (byte)'h', (byte)'e', (byte)'l', (byte)'l', (byte)'o', (byte)' ', (byte)'w', (byte)'o', (byte)'r', (byte)'l', (byte)'d', (byte)'!', (byte)'\n' };
            
            JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(encMessage);

            PGPEncryptedDataList            encList = (PGPEncryptedDataList)pgpF.nextObject();
        
            PGPPublicKeyEncryptedData    encP = (PGPPublicKeyEncryptedData)encList.get(0);

            InputStream clear = encP.getDataStream(new BcPublicKeyDataDecryptorFactory(pgpPrivKey));
                     
            pgpFact = new JcaPGPObjectFactory(clear);

            c1 = (PGPCompressedData)pgpFact.nextObject();

            pgpFact = new JcaPGPObjectFactory(c1.getDataStream());
            
            PGPLiteralData    ld = (PGPLiteralData)pgpFact.nextObject();
        
            bOut = new ByteArrayOutputStream();
            
            if (!ld.getFileName().equals("test.txt"))
            {
                throw new RuntimeException("wrong filename in packet");
            }

            InputStream    inLd = ld.getDataStream();
            
            while ((ch = inLd.read()) >= 0)
            {
                bOut.write(ch);
            }

            if (!areEqual(bOut.toByteArray(), text))
            {
                fail("wrong plain text in decrypted packet");
            }
            
            //
            // signed and encrypted message
            //
            pgpF = new JcaPGPObjectFactory(signedAndEncMessage);

            encList = (PGPEncryptedDataList)pgpF.nextObject();
        
            encP = (PGPPublicKeyEncryptedData)encList.get(0);

            clear = encP.getDataStream(new BcPublicKeyDataDecryptorFactory(pgpPrivKey));
                     
            pgpFact = new JcaPGPObjectFactory(clear);

            c1 = (PGPCompressedData)pgpFact.nextObject();

            pgpFact = new JcaPGPObjectFactory(c1.getDataStream());
            
            p1 = (PGPOnePassSignatureList)pgpFact.nextObject();
            
            ops = p1.get(0);
            
            ld = (PGPLiteralData)pgpFact.nextObject();
        
            bOut = new ByteArrayOutputStream();
            
            if (!ld.getFileName().equals("test.txt"))
            {
                throw new RuntimeException("wrong filename in packet");
            }

            inLd = ld.getDataStream();
            
            //
            // note: we use the DSA public key here.
            //
            ops.init(new BcPGPContentVerifierBuilderProvider(), pgpPub.getPublicKey());
            
            while ((ch = inLd.read()) >= 0)
            {
                ops.update((byte)ch);
                bOut.write(ch);
            }

            p3 = (PGPSignatureList)pgpFact.nextObject();

            if (!ops.verify(p3.get(0)))
            {
                fail("Failed signature check");
            }
            
            if (!areEqual(bOut.toByteArray(), text))
            {
                fail("wrong plain text in decrypted packet");
            }
            
            //
            // encrypt
            //
            ByteArrayOutputStream        cbOut = new ByteArrayOutputStream();
            PGPEncryptedDataGenerator    cPk = new PGPEncryptedDataGenerator(new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.TRIPLE_DES).setSecureRandom(new SecureRandom()));
            PGPPublicKey                        puK = sKey.getSecretKey(pgpKeyID).getPublicKey();
            
            cPk.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(puK));
            
            OutputStream    cOut = cPk.open(new UncloseableOutputStream(cbOut), bOut.toByteArray().length);

            cOut.write(text);

            cOut.close();

            pgpF = new JcaPGPObjectFactory(cbOut.toByteArray());

            encList = (PGPEncryptedDataList)pgpF.nextObject();
        
            encP = (PGPPublicKeyEncryptedData)encList.get(0);
            
            pgpPrivKey = sKey.getSecretKey(pgpKeyID).extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(pass));

            clear = encP.getDataStream(new BcPublicKeyDataDecryptorFactory(pgpPrivKey));
            
            bOut.reset();
            
            while ((ch = clear.read()) >= 0)
            {
                bOut.write(ch);
            }

            out = bOut.toByteArray();

            if (!areEqual(out, text))
            {
                fail("wrong plain text in generated packet");
            }
            
            //
            // use of PGPKeyPair
            //
            BigInteger g = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
            BigInteger p = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

            KeyPairGenerator       kpg = KeyPairGenerator.getInstance("ElGamal", "BC");
            
            ElGamalParameterSpec   elParams = new ElGamalParameterSpec(p, g);
            
            kpg.initialize(512);
            
            KeyPair kp = kpg.generateKeyPair();
            
            PGPKeyPair    pgpKp = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_GENERAL , kp, new Date());
            
            PGPPublicKey k1 = pgpKp.getPublicKey();
            
            PGPPrivateKey k2 = pgpKp.getPrivateKey();



            // Test bug with ElGamal P size != 0 mod 8 (don't use these sizes at home!)
            SecureRandom random = new SecureRandom();
            for (int pSize = 257; pSize < 264; ++pSize)
            {
                // Generate some parameters of the given size
                AlgorithmParameterGenerator a = AlgorithmParameterGenerator.getInstance("ElGamal", "BC");
                a.init(pSize, new SecureRandom());
                AlgorithmParameters params = a.generateParameters();

                DHParameterSpec elP = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ElGamal", "BC");

                keyGen.initialize(512);


                // Run a short encrypt/decrypt test with random key for the given parameters
                kp = keyGen.generateKeyPair();

                PGPKeyPair elGamalKeyPair = new JcaPGPKeyPair(
                    PublicKeyAlgorithmTags.ELGAMAL_GENERAL, kp, new Date());

                cPk = new PGPEncryptedDataGenerator(new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.CAST5).setSecureRandom(random));

                puK = elGamalKeyPair.getPublicKey();

                cPk.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(puK));

                cbOut = new ByteArrayOutputStream();

                cOut = cPk.open(cbOut, text.length);

                cOut.write(text);

                cOut.close();

                pgpF = new JcaPGPObjectFactory(cbOut.toByteArray());

                encList = (PGPEncryptedDataList)pgpF.nextObject();

                encP = (PGPPublicKeyEncryptedData)encList.get(0);

                pgpPrivKey = elGamalKeyPair.getPrivateKey();

                // Note: This is where an exception would be expected if the P size causes problems
                clear = encP.getDataStream(new BcPublicKeyDataDecryptorFactory(pgpPrivKey));

                ByteArrayOutputStream dec = new ByteArrayOutputStream();

                int b;
                while ((b = clear.read()) >= 0)
                {
                    dec.write(b);
                }

                byte[] decText = dec.toByteArray();

                if (!areEqual(text, decText))
                {
                    fail("decrypted message incorrect");
                }
            }

            // check sub key encoding

            it = pgpPub.getPublicKeys();
            while (it.hasNext())
            {
                PGPPublicKey    pgpKey = (PGPPublicKey)it.next();

                if (!pgpKey.isMasterKey())
                {
                    byte[] kEnc = pgpKey.getEncoded();

                    JcaPGPObjectFactory objF = new JcaPGPObjectFactory(kEnc);

                    PGPPublicKey k = (PGPPublicKey)objF.nextObject();

                    pKey = keyConverter.getPublicKey(k);
                    pgpKeyID = k.getKeyID();
                    if (k.getBitStrength() != 1024)
                    {
                        fail("failed - key strength reported incorrectly.");
                    }
       
                    if (objF.nextObject() != null)
                    {
                        fail("failed - stream not fully parsed.");
                    }
                }
            }
           
        }
        catch (PGPException e)
        {
            fail("exception: " + e.getMessage(), e.getUnderlyingException());
        }
    }

    public String getName()
    {
        return "PGPDSAElGamalTest";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new BcPGPDSAElGamalTest());
    }
}
