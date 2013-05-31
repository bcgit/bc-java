package org.bouncycastle.openssl.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.PasswordFinder;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.test.SimpleTestResult;

public class
    AllTests
    extends TestCase
{
    public void testOpenSSL()
    {   
        Security.addProvider(new BouncyCastleProvider());
        
        org.bouncycastle.util.test.Test[] tests = new org.bouncycastle.util.test.Test[]
        {
            new ReaderTest(),
            new WriterTest(),
            new ParserTest()
        };

        for (int i = 0; i != tests.length; i++)
        {
            SimpleTestResult  result = (SimpleTestResult)tests[i].perform();
            
            if (!result.isSuccessful())
            {
                fail(result.toString());
            }
        }
    }

    public void testPKCS8Encrypted()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(1024);

        PrivateKey key = kpGen.generateKeyPair().getPrivate();

        encryptedTest(key, PKCS8Generator.AES_256_CBC);
        encryptedTest(key, PKCS8Generator.DES3_CBC);
        encryptedTest(key, PKCS8Generator.PBE_SHA1_3DES);
        encryptedTestNew(key, PKCS8Generator.AES_256_CBC);
        encryptedTestNew(key, PKCS8Generator.DES3_CBC);
        encryptedTestNew(key, PKCS8Generator.PBE_SHA1_3DES);
    }

    private void encryptedTest(PrivateKey key, ASN1ObjectIdentifier algorithm)
        throws NoSuchProviderException, NoSuchAlgorithmException, IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PEMWriter pWrt = new PEMWriter(new OutputStreamWriter(bOut), "BC");
        PKCS8Generator pkcs8 = new PKCS8Generator(key, algorithm, "BC");

        pkcs8.setPassword("hello".toCharArray());
        
        pWrt.writeObject(pkcs8);

        pWrt.close();

        PEMReader pRd = new PEMReader(new InputStreamReader(new ByteArrayInputStream(bOut.toByteArray())), new PasswordFinder()
        {
            public char[] getPassword()
            {
                return "hello".toCharArray();
            }
        });

        PrivateKey rdKey = (PrivateKey)pRd.readObject();

        assertEquals(key, rdKey);
    }

    private void encryptedTestNew(PrivateKey key, ASN1ObjectIdentifier algorithm)
        throws NoSuchProviderException, NoSuchAlgorithmException, IOException, OperatorCreationException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PEMWriter pWrt = new PEMWriter(new OutputStreamWriter(bOut), "BC");

        JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(algorithm);

        encryptorBuilder.setProvider("BC");
        encryptorBuilder.setPasssword("hello".toCharArray());

        PKCS8Generator pkcs8 = new JcaPKCS8Generator(key, encryptorBuilder.build());

        pWrt.writeObject(pkcs8);

        pWrt.close();

        PEMReader pRd = new PEMReader(new InputStreamReader(new ByteArrayInputStream(bOut.toByteArray())), new PasswordFinder()
        {
            public char[] getPassword()
            {
                return "hello".toCharArray();
            }
        });

        PrivateKey rdKey = (PrivateKey)pRd.readObject();

        assertEquals(key, rdKey);
    }

    public void testPKCS8Plain()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(1024);

        PrivateKey key = kpGen.generateKeyPair().getPrivate();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PEMWriter pWrt = new PEMWriter(new OutputStreamWriter(bOut));
        PKCS8Generator pkcs8 = new PKCS8Generator(key);

        pWrt.writeObject(pkcs8);

        pWrt.close();

        PEMReader pRd = new PEMReader(new InputStreamReader(new ByteArrayInputStream(bOut.toByteArray())), new PasswordFinder()
        {
            public char[] getPassword()
            {
                return "hello".toCharArray();
            }
        });

        PrivateKey rdKey = (PrivateKey)pRd.readObject();

        assertEquals(key, rdKey);
    }

    public void testPKCS8PlainNew()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(1024);

        PrivateKey key = kpGen.generateKeyPair().getPrivate();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PEMWriter pWrt = new PEMWriter(new OutputStreamWriter(bOut));
        PKCS8Generator pkcs8 = new JcaPKCS8Generator(key, null);

        pWrt.writeObject(pkcs8);

        pWrt.close();

        PEMReader pRd = new PEMReader(new InputStreamReader(new ByteArrayInputStream(bOut.toByteArray())), new PasswordFinder()
        {
            public char[] getPassword()
            {
                return "hello".toCharArray();
            }
        });

        PrivateKey rdKey = (PrivateKey)pRd.readObject();

        assertEquals(key, rdKey);
    }

    public static void main (String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());
        
        junit.textui.TestRunner.run(suite());
    }
    
    public static Test suite()
    {
        TestSuite suite = new TestSuite("OpenSSL Tests");
        
        suite.addTestSuite(AllTests.class);
        
        return suite;
    }
}
