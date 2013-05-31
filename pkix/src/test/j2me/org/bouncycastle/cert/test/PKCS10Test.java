package org.bouncycastle.cert.test;

import java.math.BigInteger;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

/**
 **/
public class PKCS10Test
    extends SimpleTest
{
    private byte[] gost3410EC_A = Base64.decode(
  "MIIBOzCB6wIBADB/MQ0wCwYDVQQDEwR0ZXN0MRUwEwYDVQQKEwxEZW1vcyBDbyBMdGQxHjAcBgNV"
 +"BAsTFUNyeXB0b2dyYXBoeSBkaXZpc2lvbjEPMA0GA1UEBxMGTW9zY293MQswCQYDVQQGEwJydTEZ"
 +"MBcGCSqGSIb3DQEJARYKc2RiQGRvbC5ydTBjMBwGBiqFAwICEzASBgcqhQMCAiMBBgcqhQMCAh4B"
 +"A0MABEBYx0P2D7YuuZo5HgdIAUKAXcLBDZ+4LYFgbKjrfStVfH59lc40BQ2FZ7M703hLpXK8GiBQ"
 +"GEYpKaAuQZnMIpByoAAwCAYGKoUDAgIDA0EAgXMcTrhdOY2Er2tHOSAgnMezqrYxocZTWhxmW5Rl"
 +"JY6lbXH5rndCn4swFzXU+YhgAsJv1wQBaoZEWRl5WV4/nA==");

    private byte[] gost3410EC_B = Base64.decode(
  "MIIBPTCB7QIBADCBgDENMAsGA1UEAxMEdGVzdDEWMBQGA1UEChMNRGVtb3MgQ28gTHRkLjEeMBwG"
 +"A1UECxMVQ3J5cHRvZ3JhcGh5IGRpdmlzaW9uMQ8wDQYDVQQHEwZNb3Njb3cxCzAJBgNVBAYTAnJ1"
 +"MRkwFwYJKoZIhvcNAQkBFgpzZGJAZG9sLnJ1MGMwHAYGKoUDAgITMBIGByqFAwICIwIGByqFAwIC"
 +"HgEDQwAEQI5SLoWT7dZVilbV9j5B/fyIDuDs6x4pjqNC2TtFYbpRHrk/Wc5g/mcHvD80tsm5o1C7"
 +"7cizNzkvAVUM4VT4Dz6gADAIBgYqhQMCAgMDQQAoT5TwJ8o+bSrxckymyo3diwG7ZbSytX4sRiKy"
 +"wXPWRS9LlBvPO2NqwpS2HUnxSU8rzfL9fJcybATf7Yt1OEVq");

    private byte[] gost3410EC_C = Base64.decode(
  "MIIBRDCB9AIBADCBhzEVMBMGA1UEAxMMdGVzdCByZXF1ZXN0MRUwEwYDVQQKEwxEZW1vcyBDbyBM"
 +"dGQxHjAcBgNVBAsTFUNyeXB0b2dyYXBoeSBkaXZpc2lvbjEPMA0GA1UEBxMGTW9zY293MQswCQYD"
 +"VQQGEwJydTEZMBcGCSqGSIb3DQEJARYKc2RiQGRvbC5ydTBjMBwGBiqFAwICEzASBgcqhQMCAiMD"
 +"BgcqhQMCAh4BA0MABEBcmGh7OmR4iqqj+ycYo1S1fS7r5PhisSQU2Ezuz8wmmmR2zeTZkdMYCOBa"
 +"UTMNms0msW3wuYDho7nTDNscHTB5oAAwCAYGKoUDAgIDA0EAVoOMbfyo1Un4Ss7WQrUjHJoiaYW8"
 +"Ime5LeGGU2iW3ieAv6es/FdMrwTKkqn5dhd3aL/itFg5oQbhyfXw5yw/QQ==");
    
    private byte[] gost3410EC_ExA = Base64.decode(
     "MIIBOzCB6wIBADB/MQ0wCwYDVQQDEwR0ZXN0MRUwEwYDVQQKEwxEZW1vcyBDbyBMdGQxHjAcBgNV"
   + "BAsTFUNyeXB0b2dyYXBoeSBkaXZpc2lvbjEPMA0GA1UEBxMGTW9zY293MQswCQYDVQQGEwJydTEZ"
   + "MBcGCSqGSIb3DQEJARYKc2RiQGRvbC5ydTBjMBwGBiqFAwICEzASBgcqhQMCAiQABgcqhQMCAh4B"
   + "A0MABEDkqNT/3f8NHj6EUiWnK4JbVZBh31bEpkwq9z3jf0u8ZndG56Vt+K1ZB6EpFxLT7hSIos0w"
   + "weZ2YuTZ4w43OgodoAAwCAYGKoUDAgIDA0EASk/IUXWxoi6NtcUGVF23VRV1L3undB4sRZLp4Vho"
   + "gQ7m3CMbZFfJ2cPu6QyarseXGYHmazoirH5lGjEo535c1g==");

    private byte[] gost3410EC_ExB = Base64.decode(
      "MIIBPTCB7QIBADCBgDENMAsGA1UEAxMEdGVzdDEWMBQGA1UEChMNRGVtb3MgQ28gTHRkLjEeMBwG"
    + "A1UECxMVQ3J5cHRvZ3JhcGh5IGRpdmlzaW9uMQ8wDQYDVQQHEwZNb3Njb3cxCzAJBgNVBAYTAnJ1"
    + "MRkwFwYJKoZIhvcNAQkBFgpzZGJAZG9sLnJ1MGMwHAYGKoUDAgITMBIGByqFAwICJAEGByqFAwIC"
    + "HgEDQwAEQMBWYUKPy/1Kxad9ChAmgoSWSYOQxRnXo7KEGLU5RNSXA4qMUvArWzvhav+EYUfTbWLh"
    + "09nELDyHt2XQcvgQHnSgADAIBgYqhQMCAgMDQQAdaNhgH/ElHp64mbMaEo1tPCg9Q22McxpH8rCz"
    + "E0QBpF4H5mSSQVGI5OAXHToetnNuh7gHHSynyCupYDEHTbkZ");

    public String getName()
    {
        return "PKCS10CertRequest";
    }

    private void rsaCreationTest()
        throws Exception
    {
        //
        // a lightweight key pair.
        //
        RSAKeyParameters lwPubKey = new RSAKeyParameters(
            false,
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16));

        RSAPrivateCrtKeyParameters lwPrivKey = new RSAPrivateCrtKeyParameters(
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16),
            new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
            new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
            new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
            new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
            new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
            new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));

        //
        // distinguished name table.
        //
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);

        builder.addRDN(BCStyle.C, "AU");
        builder.addRDN(BCStyle.O, "The Legion of the Bouncy Castle");
        builder.addRDN(BCStyle.L, "Melbourne");
        builder.addRDN(BCStyle.ST, "Victoria");
        builder.addRDN(BCStyle.E, "feedback-crypto@bouncycastle.org");

        //
        // extensions
        //

        //
        // create the certificate - version 3 - without extensions
        //
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256WithRSAEncryption");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

        ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(lwPrivKey);
        SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), new RSAPublicKey(lwPubKey.getModulus(), lwPubKey.getExponent()));

        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE);

        x500NameBld.addRDN(BCStyle.C, "AU");
        x500NameBld.addRDN(BCStyle.O, "The Legion of the Bouncy Castle");
        x500NameBld.addRDN(BCStyle.L, "Melbourne");
        x500NameBld.addRDN(BCStyle.ST, "Victoria");
        x500NameBld.addRDN(BCStyle.EmailAddress, "feedback-crypto@bouncycastle.org");

        X500Name    subject = x500NameBld.build();

        PKCS10CertificationRequestBuilder requestBuilder = new PKCS10CertificationRequestBuilder(subject, pubInfo);
                            
        PKCS10CertificationRequest req1 = requestBuilder.build(sigGen);

        PKCS10CertificationRequest req2 = new PKCS10CertificationRequest(req1.getEncoded());

        if (!req2.isSignatureValid(new BcRSAContentVerifierProviderBuilder(new DefaultDigestAlgorithmIdentifierFinder()).build(lwPubKey)))
        {
            fail("Failed verify check.");
        }

        if (!Arrays.areEqual(req2.getSubjectPublicKeyInfo().getEncoded(), req1.getSubjectPublicKeyInfo().getEncoded()))
        {
            fail("Failed public key check.");
        }
    }

    public void performTest()
        throws Exception
    {
        rsaCreationTest();
    }

    public static void main(
        String[]    args)
    {
        runTest(new PKCS10Test());
    }
}
