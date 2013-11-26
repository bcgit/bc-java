package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import javax.crypto.Cipher;

import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class PGPDSAElGamalTest implements Test
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
    
    private boolean notEqual(
        byte[]    b1,
        byte[]    b2)
    {
        if (b1.length != b2.length)
        {
            return true;
        }
        
        for (int i = 0; i != b2.length; i++)
        {
            if (b1[i] != b2[i])
            {
                return true;
            }
        }
        
        return false;
    }
    
    public TestResult perform()
    {
        try
        {
            String file = null;
            KeyFactory fact = KeyFactory.getInstance("DSA", "BC");
            PGPPublicKey pubKey = null;
            PrivateKey privKey = null;
            
            PGPUtil.setDefaultProvider("BC");

            //
            // Read the public key
            //
            PGPObjectFactory    pgpFact = new PGPObjectFactory(testPubKeyRing);
            
            PGPPublicKeyRing        pgpPub = (PGPPublicKeyRing)pgpFact.nextObject();

               pubKey = pgpPub.getPublicKey();

            //
            // Read the private key
            //
            PGPSecretKeyRing    sKey = new PGPSecretKeyRing(testPrivKeyRing);
            PGPPrivateKey        pgpPrivKey = sKey.getSecretKey().extractPrivateKey(pass, "BC");
            
            //
            // signature generation
            //
            String                                data = "hello world!";
            ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
            ByteArrayInputStream        testIn = new ByteArrayInputStream(data.getBytes());
            PGPSignatureGenerator    sGen = new PGPSignatureGenerator(PGPPublicKey.DSA, PGPUtil.SHA1, "BC");
        
            sGen.initSign(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

            PGPCompressedDataGenerator cGen = new PGPCompressedDataGenerator(
                                                                    PGPCompressedData.ZIP);

            BCPGOutputStream            bcOut = new BCPGOutputStream(cGen.open(bOut));

            sGen.generateOnePassVersion(false).encode(bcOut);

            PGPLiteralDataGenerator    lGen = new PGPLiteralDataGenerator();
            OutputStream                    lOut = lGen.open(bcOut, PGPLiteralData.BINARY, "_CONSOLE", data.getBytes().length, new Date());
            int                                    ch;
            
            while ((ch = testIn.read()) >= 0)
            {
                lOut.write(ch);
                sGen.update((byte)ch);
            }

            sGen.generate().encode(bcOut);

            lGen.close();

            cGen.close();

            //
            // verify generated signature
            //
            pgpFact = new PGPObjectFactory(bOut.toByteArray());

            PGPCompressedData c1 = (PGPCompressedData)pgpFact.nextObject();

            pgpFact = new PGPObjectFactory(c1.getDataStream());
            
            PGPOnePassSignatureList p1 = (PGPOnePassSignatureList)pgpFact.nextObject();
            
            PGPOnePassSignature ops = p1.get(0);
            
            PGPLiteralData p2 = (PGPLiteralData)pgpFact.nextObject();

            InputStream    dIn = p2.getInputStream();

            ops.initVerify(pubKey, "BC");
            
            while ((ch = dIn.read()) >= 0)
            {
                ops.update((byte)ch);
            }

            PGPSignatureList p3 = (PGPSignatureList)pgpFact.nextObject();

            if (!ops.verify(p3.get(0)))
            {
                return new SimpleTestResult(false, getName() + ": Failed generated signature check");
            }
            
            //
            // test encryption
            //
            
            //
            // find a key sutiable for encryption
            //
            long            pgpKeyID = 0;
            PublicKey    pKey = null;
            
            Iterator    it = pgpPub.getPublicKeys();
            while (it.hasNext())
            {
                PGPPublicKey    pgpKey = (PGPPublicKey)it.next();

                if (pgpKey.getAlgorithm() == PGPPublicKey.ELGAMAL_ENCRYPT
                    || pgpKey.getAlgorithm() == PGPPublicKey.ELGAMAL_GENERAL)
                {
                    pKey = pgpKey.getKey("BC");
                    pgpKeyID = pgpKey.getKeyID();
                    
                    //
                    // verify the key
                    //
                    
                }
            }
             
            Cipher c = Cipher.getInstance("ElGamal/None/PKCS1Padding", "BC");

            c.init(Cipher.ENCRYPT_MODE, pKey);
            
            byte[]  in = "hello world".getBytes();

            byte[]  out = c.doFinal(in);
            
            pgpPrivKey = sKey.getSecretKey(pgpKeyID).extractPrivateKey(pass, "BC");
            
            c.init(Cipher.DECRYPT_MODE, pgpPrivKey.getKey());
            
            out = c.doFinal(out);
            
            if (notEqual(in, out))
            {
                return new SimpleTestResult(false, getName() + ": decryption failed.");
            }

            //
            // encrypted message
            //
            byte[]    text = { (byte)'h', (byte)'e', (byte)'l', (byte)'l', (byte)'o', (byte)' ', (byte)'w', (byte)'o', (byte)'r', (byte)'l', (byte)'d', (byte)'!', (byte)'\n' };
            
            PGPObjectFactory pgpF = new PGPObjectFactory(encMessage);

            PGPEncryptedDataList            encList = (PGPEncryptedDataList)pgpF.nextObject();
        
            PGPPublicKeyEncryptedData    encP = (PGPPublicKeyEncryptedData)encList.get(0);

            InputStream clear = encP.getDataStream(pgpPrivKey, "BC");
                     
            pgpFact = new PGPObjectFactory(clear);

            c1 = (PGPCompressedData)pgpFact.nextObject();

            pgpFact = new PGPObjectFactory(c1.getDataStream());
            
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

            if (notEqual(bOut.toByteArray(), text))
            {
                return new SimpleTestResult(false, getName() + ": wrong plain text in decrypted packet");
            }
            
            //
            // signed and encrypted message
            //
            pgpF = new PGPObjectFactory(signedAndEncMessage);

            encList = (PGPEncryptedDataList)pgpF.nextObject();
        
            encP = (PGPPublicKeyEncryptedData)encList.get(0);

            clear = encP.getDataStream(pgpPrivKey, "BC");
                     
            pgpFact = new PGPObjectFactory(clear);

            c1 = (PGPCompressedData)pgpFact.nextObject();

            pgpFact = new PGPObjectFactory(c1.getDataStream());
            
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
            ops.initVerify(pgpPub.getPublicKey(), "BC");
            
            while ((ch = inLd.read()) >= 0)
            {
                ops.update((byte)ch);
                bOut.write(ch);
            }

            p3 = (PGPSignatureList)pgpFact.nextObject();

            if (!ops.verify(p3.get(0)))
            {
                return new SimpleTestResult(false, getName() + ": Failed signature check");
            }
            
            if (notEqual(bOut.toByteArray(), text))
            {
                return new SimpleTestResult(false, getName() + ": wrong plain text in decrypted packet");
            }
            
            //
            // encrypt
            //
            ByteArrayOutputStream        cbOut = new ByteArrayOutputStream();
            PGPEncryptedDataGenerator    cPk = new PGPEncryptedDataGenerator(SymmetricKeyAlgorithmTags.TRIPLE_DES, new SecureRandom(), "BC");            
            PGPPublicKey                        puK = sKey.getSecretKey(pgpKeyID).getPublicKey();
            
            cPk.addMethod(puK);
            
            OutputStream    cOut = cPk.open(cbOut, bOut.toByteArray().length);

            cOut.write(text);

            cOut.close();

            pgpF = new PGPObjectFactory(cbOut.toByteArray());

            encList = (PGPEncryptedDataList)pgpF.nextObject();
        
            encP = (PGPPublicKeyEncryptedData)encList.get(0);
            
            pgpPrivKey = sKey.getSecretKey(pgpKeyID).extractPrivateKey(pass, "BC");

            clear = encP.getDataStream(pgpPrivKey, "BC");
            
            bOut.reset();
            
            while ((ch = clear.read()) >= 0)
            {
                bOut.write(ch);
            }

            out = bOut.toByteArray();

            if (notEqual(out, text))
            {
                return new SimpleTestResult(false, getName() + ": wrong plain text in generated packet");
            }
            
            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
            e.printStackTrace();
            if (e instanceof PGPException)
            {
                ((PGPException)e).getUnderlyingException().printStackTrace();
            }
            return new SimpleTestResult(false, getName() + ": exception - " + e.toString());
        }
    }

    public String getName()
    {
        return "PGPDSAElGamalTest";
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test test = new PGPDSAElGamalTest();
        TestResult result = test.perform();

        System.out.println(result.toString());
        if (result.getException() != null)
        {
            result.getException().printStackTrace();
        }
    }
}
