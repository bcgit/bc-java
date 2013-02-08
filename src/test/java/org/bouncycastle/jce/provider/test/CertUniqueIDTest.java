package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;
import java.util.Set;
import java.util.Vector;

import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class CertUniqueIDTest
    extends SimpleTest
{
  public String getName()
  {
      return "CertUniqueID";
  }

  public void performTest() throws Exception
  {
    checkCreation1();
  }

  /**
   * we generate a self signed certificate for the sake of testing - RSA
   */
  public void checkCreation1()
      throws Exception
  {
      //
      // a sample key pair.
      //
      RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
          new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
          new BigInteger("11", 16));

      RSAPrivateCrtKeySpec privKeySpec = new RSAPrivateCrtKeySpec(
          new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
          new BigInteger("11", 16),
          new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
          new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
          new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
          new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
          new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
          new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));

      //
      // set up the keys
      //
      PrivateKey          privKey;
      PublicKey           pubKey;

      KeyFactory  fact = KeyFactory.getInstance("RSA", "BC");

      privKey = fact.generatePrivate(privKeySpec);
      pubKey = fact.generatePublic(pubKeySpec);

      //
      // distinguished name table.
      //
      Vector                      ord = new Vector();
      Vector                      values = new Vector();

      ord.addElement(X509Principal.C);
      ord.addElement(X509Principal.O);
      ord.addElement(X509Principal.L);
      ord.addElement(X509Principal.ST);
      ord.addElement(X509Principal.E);

      values.addElement("AU");
      values.addElement("The Legion of the Bouncy Castle");
      values.addElement("Melbourne");
      values.addElement("Victoria");
      values.addElement("feedback-crypto@bouncycastle.org");

      //
      // extensions
      //

      //
      // create the certificate - version 3 - without subject unique ID
      //
      X509V3CertificateGenerator  certGen = new X509V3CertificateGenerator();

      certGen.setSerialNumber(BigInteger.valueOf(1));
      certGen.setIssuerDN(new X509Principal(ord, values));
      certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
      certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
      certGen.setSubjectDN(new X509Principal(ord, values));
      certGen.setPublicKey(pubKey);
      certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

      X509Certificate cert = certGen.generate(privKey);

      cert.checkValidity(new Date());

      cert.verify(pubKey);

      Set dummySet = cert.getNonCriticalExtensionOIDs();
      if (dummySet != null)
      {
          fail("non-critical oid set should be null");
      }
      dummySet = cert.getCriticalExtensionOIDs();
      if (dummySet != null)
      {
          fail("critical oid set should be null");
      }

      //
      // create the certificate - version 3 - with subject unique ID
      //
      certGen = new X509V3CertificateGenerator();

      certGen.setSerialNumber(BigInteger.valueOf(1));
      certGen.setIssuerDN(new X509Principal(ord, values));
      certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
      certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
      certGen.setSubjectDN(new X509Principal(ord, values));
      certGen.setPublicKey(pubKey);
      certGen.setSignatureAlgorithm("MD5WithRSAEncryption");

      boolean[] subjectUniqID = {true, false, false, false, true, false, false, true, false, true, true};

      certGen.setSubjectUniqueID(subjectUniqID);

      boolean[] issuerUniqID = {false, false, true, false, true, false, false, false, true, false, false, true, false, true, true};

      certGen.setIssuerUniqueID(issuerUniqID);

      cert = certGen.generate(privKey);

      cert.checkValidity(new Date());

      cert.verify(pubKey);

      boolean[] subjectUniqueId = cert.getSubjectUniqueID();
      if (!Arrays.areEqual(subjectUniqID, subjectUniqueId))
      {
          fail("Subject unique id is not correct, original: "+arrayToString(subjectUniqID)+", from cert: "+arrayToString(subjectUniqueId));
      }

      boolean[] issuerUniqueId = cert.getIssuerUniqueID();
      if (!Arrays.areEqual(issuerUniqID, issuerUniqueId))
      {
          fail("Issuer unique id is not correct, original: "+arrayToString(issuerUniqID)+", from cert: "+arrayToString(subjectUniqueId));
      }
  }

  private String arrayToString(boolean[] array)
  {
      StringBuffer b = new StringBuffer();

      for (int i = 0; i != array.length; i++)
      {
          b.append(array[i] ? "1" : "0");
      }

      return b.toString();
  }
  public static void main(
      String[]    args)
  {
      Security.addProvider(new BouncyCastleProvider());

      runTest(new CertUniqueIDTest());
  }
}
