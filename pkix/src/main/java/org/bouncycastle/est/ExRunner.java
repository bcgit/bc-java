package org.bouncycastle.est;


import java.math.BigInteger;
import java.net.URL;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPathValidator;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.path.CertPath;
import org.bouncycastle.cert.path.CertPathValidation;
import org.bouncycastle.est.functions.FetchCACerts;
import org.bouncycastle.est.functions.SimpleEnroll;
import org.bouncycastle.est.http.DefaultESTClient;
import org.bouncycastle.est.http.DefaultESTClientSSLSocketProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.Store;


/**
 * Simple runner for development outside of testing.
 * This is _not_ api.
 */
public class ExRunner
{
    public static void main(String[] args)
        throws Exception
    {
        new ExRunner(args);
    }

    private ExRunner(String[] args)
        throws Exception
    {
        X509CertificateHolder[] theirCAs = null;

        Security.addProvider(new BouncyCastleProvider());
        {
            String testURL = "https://testrfc7030.cisco.com:8443/.well-known/est/cacerts";

            //
            // Fetch using the default SSLSocket factory
            // No Hostname verification or boot strap authorizer.
            //
            FetchCACerts fetchCACerts = new FetchCACerts(
                new DefaultESTClient(
                    DefaultESTClientSSLSocketProvider.getUsingDefaultSSLSocketFactory(null)));

            Store<X509CertificateHolder> store = fetchCACerts.getCertificates(new URL(testURL), null);

            Collection<X509CertificateHolder> all = store.getMatches(null);
//            CertPath cp = new CertPath(all.toArray(new X509CertificateHolder[all.size()]));

            List<X509CertificateHolder> cas = new ArrayList<X509CertificateHolder>();

            for (X509CertificateHolder h : all)
            {

                if (BasicConstraints.fromExtensions(h.getExtensions()).isCA())
                {
                    cas.add(h);
                }

                System.out.println(h.getSubject());
                System.out.println(h.getIssuer());
            }
            theirCAs = cas.toArray(new X509CertificateHolder[cas.size()]);
        }

        //
        // Simple Enrol
        //
        {
            String testURL = "https://testrfc7030.cisco.com:8443/.well-known/est/simpleenroll";

            final RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
                new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
                new BigInteger("11", 16));

            final RSAPrivateCrtKeySpec privKeySpec = new RSAPrivateCrtKeySpec(
                new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
                new BigInteger("11", 16),
                new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
                new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
                new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
                new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
                new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
                new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));


            // Make CSR
            KeyFactory keyFact = KeyFactory.getInstance("RSA", "BC");
            PublicKey pubKey = keyFact.generatePublic(pubKeySpec);
            PrivateKey privKey = keyFact.generatePrivate(privKeySpec);

            PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Test"), pubKey);

            final PKCS10CertificationRequest request = pkcs10Builder.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privKey));

            SimpleEnroll se = new SimpleEnroll(new DefaultESTClient(
                DefaultESTClientSSLSocketProvider.getUsingDefaultSSLSocketFactory(null)));
            Store<X509CertificateHolder> store = se.simpleEnrolBasicAuth(new URL(testURL), "estuser", "estpwd", request);

            Collection<X509CertificateHolder> all = store.getMatches(null);

            for (X509CertificateHolder h : all)
            {
                System.out.println(h.getSubject());
                System.out.println(h.getIssuer());
            }

        }


    }


}
