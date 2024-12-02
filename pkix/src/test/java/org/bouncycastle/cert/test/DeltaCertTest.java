package org.bouncycastle.cert.test;

import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import junit.framework.TestCase;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.DeltaCertificateDescriptor;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.DeltaCertificateTool;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.encoders.Base64;

public class DeltaCertTest
    extends TestCase
{
    private static byte[] deltaCertReq = Base64.decode(
        "MIIP2zCCD4ACAQAwDzENMAsGA1UEAwwEVGVzdDBZMBMGByqGSM49AgEGCCqGSM49\n" +
            "AwEHA0IABEqIRHVQv5GkHTHTBzPZFAiCVbMB8h+uTZ1gV58O2rnCBn4YNqpIj8j0\n" +
            "3w2myhahWFeyw/Yjq1CgyvbjbglieUuggg8NMIIFfAYKYIZIAYb6a1AGAjGCBWww\n" +
            "ggVooB8wHTEbMBkGA1UEAwwSRGlsMiBDZXJ0IFJlcSBUZXN0MIIFNDANBgsrBgEE\n" +
            "AQKCCwwEBAOCBSEA8FVxiaOOy6Q3iNLf6l0teGHOuJq8kXEd4uHXmVDBgZOvb90c\n" +
            "8frAULVblAD2Ky6c9Ra/BcjXtenWXDxrd18ky0s0E/YmT6tUVMDNCT0htbU2ONnl\n" +
            "8YDpsROlO1HHZwV9yYDolEeu2MJTwmQ42f+1udRt37KctrQ2OzvktRp1wvyz1EOm\n" +
            "0T0ORrHi3pS95d74ZEMlRdtG1KAW0vZ85SrNZu5TJ000ODBgvyIgsYPTwGDineMU\n" +
            "Vd2A/1DIhBpwFmv5lKeOLGVBZ9TqonlLuQYKVSWTt4MLW9BAl2S8AKP1XKqc8hsr\n" +
            "qpgcl6pokVYNbnwNfAKECtpy8yNJm8+5t254zwdcGMVPUFPcaincq1nYyc0OhBBZ\n" +
            "rd4tiVnv7anCOtapLewfuU/M60TWr83QKLfgiDb63OHrSLR1GSwPNcfY6GjttweQ\n" +
            "mHoQn/ymMxLF2aUB5KRN1J42r8tUYaLd4/NPIyrW3PuuD5xStnfP5Sm4kTxq3ZlB\n" +
            "Sg3kVIQW3k3Ue0a2fy83oT2nzasddu9ZaKzgox9cQN0eekm9LIzSjoLtDWqbSHpS\n" +
            "AwIvYtTRoORh/+pyJPefGo647yzvKnvyh7300d/OLPeMoErs3RptXRD8x9YiKnYg\n" +
            "uLfxMnIZB5Dmb+JSz3e4E3j3pl8/RkIbXpX4nU1Ng6PgVUiwu1/5swOL4tTsI8dN\n" +
            "7DJiY6WmjjNtkJX9YlWIAK7j2jZ6Bi7/s8saAXh0YmB94UI4opnuLbAJWVauSU22\n" +
            "TUR/qb6NNdHN9Db+EBkHnS5MAeve5jRZVsb0yTy4pmr4n85Go1h+KxZsd9MIJQu4\n" +
            "sN564qVeJ355hloKyXf7nApDWbkqCGAXjdSizhLkZ5hnm5tL/qTrgg7MldtlYEtH\n" +
            "ksmPGeeLEF3te2VKt1gSesJmeJkgvYczi0t4fAWpkZCbQe0rBp3J8SGRw7UuDAez\n" +
            "9rYvXdHIO+TSdUaWnhPZPTXEPJD8hodBok5Z5oJbKEtzb3kCkmz8OBf3sFGblLit\n" +
            "EHCTW25X/fRI3HpKqWy2J5wND5asyyPFzMXGYJJGx0eN3V3EFcs7pJXOmJlQfuJo\n" +
            "Q656TWsxzKJQGnwESqzOC/jnliYFX6ilab41CRJZXXJOMC0EYbcmaDsGouCQAJ8x\n" +
            "BacyWNzl3YCibK3SfCecXvMbOxx5xuNZju3KwYZtywmN9YBGqeht5FDH197KW7t1\n" +
            "lUA4H+cT+CUDSWQXfMHlOeJaLQFsOC+wACD3jIw8lObWTdssl6nLlf6L6xuCbGj3\n" +
            "pUgXLXa4VZNBXaoh6JgasuBsmXColmEwTmLNwxFrFKUl/DH1VW6zJRUc4RMD18kb\n" +
            "ys09EryX52vuTL23FOcqKqoIbQUkav1hEtGIGeArW1EpcQRRXEs++VOKSXr2Vm5m\n" +
            "efpKP1EShkjnBLuJxM5ybklnWp5Y9UIOIicl78nFq/yMTXrVZSnVcqC3ubnBg2O0\n" +
            "1++7R8XID0PUX6FK9FaK1Tu5D0I0X5p0Dntmf5VF/EsA7OF5Cmm+kPtLHn+XClEJ\n" +
            "w9SnrboMLa/Ltd0gML9mLanrv8UTKpVyFKD5B+Qiuzd+3HtxDbXZHjN5/AC7ibuZ\n" +
            "DuSWbi6U6N00VNmSzZ4IwmfNTdCkIPLGIFSJ2dhrp5P2oDfeIfapZtFukuWu/iA4\n" +
            "/iT43OeNMXwCg9wVb6cXBeJTifOAm/Rqm42UaDqsyk/za1M6YW/pYDNQzJBvvMqZ\n" +
            "p92GMQjDEqXv0dyIXzWBwDc+RUyATSY5mnn6O6INBgsrBgEEAQKCCwwEBDCCCYkG\n" +
            "CmCGSAGG+mtQBgMxggl5A4IJdQBmEI0USeb3jHLoswVnkl6bhVdCdu4YBoPWZMX1\n" +
            "4Ka4489Ns6pSgL5ex3r1W/4ZeI5XWqIqUXDIwwW2hp+OHLvFM3jbA3Weul/bL/yJ\n" +
            "pz9io3m++CKYP4KCMssDoyBwvTR5oX28yq9lc0L7uhgtWyACQP/x0kvci32pDQvb\n" +
            "GfcZcXGmgEmK4xRWOfnphwPSXGmyhH4+TeTua/u5+Ka1ShMjs7G/1G07CaM53Un4\n" +
            "mZm3gb6cbNGWxxRpfB7/lQs7ckjoA/Jx/r94uKz1wGHXkoyx9QEzjkHvR60i4REr\n" +
            "+Gk0kJhSaKmw15NMKJJJ0iMINWlzKZCnd2oL0eMIjHs2dx+H5Ea+DlveI9VNddDy\n" +
            "9bi/WeSySS3HdorakMCbIr862W3DLrIRupi4gPI+E/VKqD8cCLvzs1Ffgfe5MCi+\n" +
            "WDxu+7NGlGmd12LDr8NfwvvlvLioWsiSWWXRvONfgj2vrneRGGpP85COQbtzt+5h\n" +
            "N925iY3uD5qpKap0nQiWCjWVKMRFJXl7b2brouQu6qu7i1kyqpTOenNUXidgAtkM\n" +
            "5LC2Nsejyci1FPGbU/5JR+71tMA2aJ9Wku4hCI3IWfgQBNJ9YDCvahqSeILtHpTA\n" +
            "6IxjcQ6PCPAORFCyM+MHMrAr/y+SNMB7zoKkq/m9Rng2Z2artdZ5VtvigHbhg/FP\n" +
            "BP58laYE+LZ/NkVWp3BjQQow2MJujy9dzgOeU6ih0jjG3tg0QW0RuSloNhUfI1rZ\n" +
            "UAfqadFcy1nNtZMHEUM4F36Tx9kkPBeTaN/OJIa8ICNI9yNwxMOIRYmXlXldqQcM\n" +
            "lPzKuEeiHBwt5T/5piOynYSzNiE/1M9ILo87KjSLSv1BQZR+lI6kpmFZj7FFWyde\n" +
            "WFxvRCBeZNmMwQhIO9t1ZfqZzKCJ8ADqYhol9CZatyqVXNo8FR7BVnHFHcIM1JCf\n" +
            "A8/T4pTz9B6OZb+35fCeznyNe0XckfRYRmAtFrJOikMSF/YF6ZvYqd/eJLvs35it\n" +
            "cCE6Y/liPFS8QG2oPBunCGxLp3wWo11YsO4ViOfHjrV2aHhYM/aQvLWwgR+xqdXq\n" +
            "xrm3xWtLr1u3EpRLWouMDuiCyqCtAwsra4UyyO1tFRLsYuGAZTQZ+JCjO1TOYmdE\n" +
            "vk+CkS3fBTeajFbBIrMJY5WIFdHWcbjIQd6rRHkpNMN0RnytL9X9P7s1hxyhfOM3\n" +
            "BLAguLuuoIyWwmXkvxWOu52i0NIdAuv9PXv2d+l5LYd8Tqz9Uw2DUSHj6bIQZhdH\n" +
            "0k1rw8PkxYT0LXM5zmXPxlVKg1uHDkRn/rf7bkhQ16GV4evF2Pwfg0JS85aE6WA7\n" +
            "+3RjAi+pc2NhWHtNObVvEv/Cr7MT6jLk242TZBk7z9h/xsa6HHIM95bmpmqPMm1D\n" +
            "j4hT6eHosVynhgXQYYuJixV65mFQOjJFhzGi1mP4jLOggZ81Bjq1yg5+Kor1CGPT\n" +
            "ufbHkr60o0FTu49ASWgLLLr1k1RQBNjADcDQfmUio+XJJfZQlfTiYx25IaxX/uha\n" +
            "0WZYJo/8UNfjsw15pQSSQf/o+NQwvCs7pWJoa4D9mhzGlAakI+33A89nt+W7szbN\n" +
            "5f00CpJI5UUv/k5E1hDSVR1FeCq0DRruBEVF+YAHKWPEEdCGoc5x0QnHiiZeAQQ9\n" +
            "Z49VJSXxRjK+vzKl4mmQPYJtA2sAm2CrGYYYujJQ+hk6M3HL3iA+IyMczpTwtHCi\n" +
            "ImOZxNt8yt6xlpYhUoHhwD8+QVI1IPWiciIseCzfdYK9ZZVO1QeQTyqVLflXeMOK\n" +
            "snpuAQTPXEcxylVtG0Gqux7BQM7REYb1VEgIzEQ80CyL9CeXOzQRojlNB5k9tVZ7\n" +
            "cUIEaAzNrqX8iJtyhUkxuIlmodnMkMlMWDFMn+gz1SA3+nAGT1/ea6RS96R7xUAN\n" +
            "tzvMxqrQSctz/+EkGwnF7HVq5t+YG5rCWYm8w+ZuB/MXbFobvccChjBL0LE+sTqr\n" +
            "vkbKqzRgVgqkW27x+BVxRCXtAbgEknsvmVFWzb6/ez/6eyRvJX1WgwlWsS5X66CE\n" +
            "HD3W2rnCasL32g1iLVhb7GPfOi+37yjVwCpV+PHAVYEGvYeuNDovsHuYnPk2lh8Q\n" +
            "WWqj0ws0tniCXxaQxgC5QVbQsuideloPnJwWNDSSeTG2OALoiVC1mXNTbkLZyDbe\n" +
            "9m3VmCfWHXONtrICAaXk8Zrvy0rJWTkOK/yo1RIALJirZqAewcf+pr13k8ZZCUB+\n" +
            "rN74OwWsTztpBkHuFZjJc4FZXagvS+f+TtDvk12aR0ka6VvW+zLMdFiDiaPcub4B\n" +
            "11guEYLkqCg7yFuocqn+9UBA/Jued8HQDnmW13D498qvp5nWOz/Vnk5F6rf882iL\n" +
            "Ex0MDvXnEFfWPOnYQ0mETWWvmhYTzlVUGhrN0WHi9MTyRByWZ4m48+wfKhtyDbEV\n" +
            "on3X+dRqdlqdaGKtXjGAByForcym7mescUF9r5gu/EDICYtek9iPQqlXY0u2Yrp6\n" +
            "8Q5zMUOwjVoTjWHVDIgOVjHGBoBgCPUwzgrVQuOMy411yvm+DYUdtvoWpYTAGNo2\n" +
            "RX1yeDROevYe0p4Nk34HoYX2cj8+Ov9KoDNf2SgH3uAdz8SFl6U7F+ef6SpOxFSY\n" +
            "s+VV7H8V+XQ59WqNbZbf70vRPlNd1gpjI3iksBehGHX/n6L2hPIwQnvvVCJbffEC\n" +
            "DsFykZo9KpgvbRetwSwOLYoGUhQDb0dIx6WyATj3klJNtYJiLweb5PaelwZ8fkJV\n" +
            "+vksYRenfwm+VaMiLtFWd4oHR+zPtLwUMvKMzqOeEe3VhMvzxM356LzeZyfjz6uF\n" +
            "negEdIn8G0Xb+i91SKKZWVl+1jBXE6ov40/SFfneHi54uA1/9JPf5K4aES7yTtml\n" +
            "ffk6Nc5Z54zFkhO0ggWgEJt7CT/eQDz5jqAT40Q7lbIxvQcPdG90WmmhxjOGKfLF\n" +
            "Ug/FQuG+dlw4xBCIEC04zBjC5TrCbSjNm0xGkHCeKEIzIN3eIKbQ8S7Fs4zKqn1i\n" +
            "w3kRxcb928h6xfb2SsESKF/9U/8kOpNITE+XPug+WYLzfh8BS8kfxut3GGTArYAn\n" +
            "TCOOooJldukCPIxd5Nf1SAitlbUyfjY9i2xWDUiMdPxNYtSZ5f9HgDgcHSTrm9EB\n" +
            "SMAl1jtCUmN+hpmkp9Dh4+vx+0NfYmlzhomcqa271djb6e31AxEdJCYoMTZWb3uL\n" +
            "utjg5Ojr8v0BHiEoQ0tUjZGam6S7xcfP09vj+/0AAAAAAAAADyA0STAKBggqhkjO\n" +
            "PQQDAgNJADBGAiEA8Yi24L05Pkn0y6Umltpd6Hhw/TyFzB7SmaEEEcn9+iYCIQCA\n" +
            "ahofKFqOtfmLrzh+a8VCq30wqdJhqf+imN28KcziNA==");

    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testSameName()
        throws Exception
    {
        KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA", "BC");
        rsaKeyGen.initialize(2048, new java.security.SecureRandom());
        java.security.KeyPair deltaKeyPair = rsaKeyGen.generateKeyPair();
        java.security.KeyPair baseKeyPair = rsaKeyGen.generateKeyPair();

        // Generate a self-signed Delta Certificate
        X509v3CertificateBuilder deltaCertBuilder = new X509v3CertificateBuilder(
            new X500Name("CN=Issuer"),
            java.math.BigInteger.valueOf(1L),
            new java.util.Date(System.currentTimeMillis()),
            new java.util.Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000),
            new X500Name("CN=Subject"),
            SubjectPublicKeyInfo.getInstance(deltaKeyPair.getPublic().getEncoded())
        );
        ContentSigner deltaRootSigner = new JcaContentSignerBuilder("SHA256withRSA").build(deltaKeyPair.getPrivate());
        X509CertificateHolder deltaCert = deltaCertBuilder.build(deltaRootSigner);

        // Generate a self-signed Base Certificate
        X509v3CertificateBuilder baseCertBuilder = new X509v3CertificateBuilder(
            new X500Name("CN=Issuer"), // Same as Delta Certificate
            java.math.BigInteger.valueOf(2L),
            new java.util.Date(System.currentTimeMillis()),
            new java.util.Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000),
            new X500Name("CN=Subject"), // Same as Delta Certificate
            SubjectPublicKeyInfo.getInstance(baseKeyPair.getPublic().getEncoded())
        );

        // Create Delta Extension
        Extension deltaCertExtension = DeltaCertificateTool.makeDeltaCertificateExtension(false, deltaCert);
        // Add Delta Extension to Base Certificate
        baseCertBuilder.addExtension(deltaCertExtension);
        // Build Base Certificate
        ContentSigner baseRootSigner = new JcaContentSignerBuilder("SHA256withRSA").build(baseKeyPair.getPrivate());
        X509CertificateHolder baseCert = baseCertBuilder.build(baseRootSigner); // <= Exception thrown here
    }
    
    // TODO: add new request data (change to explicit tags)
//    public void testDeltaCertRequest()
//        throws Exception
//    {
//        PKCS10CertificationRequest pkcs10CertReq = new PKCS10CertificationRequest(deltaCertReq);
//
//        assertTrue(pkcs10CertReq.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(pkcs10CertReq.getSubjectPublicKeyInfo())));
//
//        Attribute[] attributes = pkcs10CertReq.getAttributes(new ASN1ObjectIdentifier("2.16.840.1.114027.80.6.2"));
//
//        DeltaCertificateRequestAttributeValue deltaReq = new DeltaCertificateRequestAttributeValue(attributes[0]);
//
//        assertTrue(DeltaCertAttributeUtils.isDeltaRequestSignatureValid(pkcs10CertReq, new JcaContentVerifierProviderBuilder().setProvider("BC").build(deltaReq.getSubjectPKInfo())));
//
//        KeyPairGenerator kpgB = KeyPairGenerator.getInstance("EC", "BC");
//
//        kpgB.initialize(new ECNamedCurveGenParameterSpec("P-256"));
//
//        KeyPair kpB = kpgB.generateKeyPair();
//
//        Date notBefore = new Date(System.currentTimeMillis() - 5000);
//        Date notAfter = new Date(System.currentTimeMillis() + 1000 * 60 * 60);
//        X509v3CertificateBuilder bldr = new X509v3CertificateBuilder(
//            new X500Name("CN=Chameleon CA 1"),
//            BigInteger.valueOf(System.currentTimeMillis()),
//            notBefore,
//            notAfter,
//            pkcs10CertReq.getSubject(),
//            pkcs10CertReq.getSubjectPublicKeyInfo());
//
//        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(kpB.getPrivate());
//
//        X509v3CertificateBuilder deltaBldr = new X509v3CertificateBuilder(
//                    new X500Name("CN=Chameleon CA 2"),
//                    BigInteger.valueOf(System.currentTimeMillis()),
//                    notBefore,
//                    notAfter,
//                    deltaReq.getSubject(),
//                    deltaReq.getSubjectPKInfo());
//        if (deltaReq.getExtensions() != null)
//        {
//            Extensions extensions = deltaReq.getExtensions();
//            for (Enumeration e = extensions.oids(); e.hasMoreElements();)
//            {
//                deltaBldr.addExtension(extensions.getExtension((ASN1ObjectIdentifier)e.nextElement()));
//            }
//        }
//
//        X509CertificateHolder deltaCert = deltaBldr.build(signer);
//
//        Extension deltaExt = DeltaCertificateTool.makeDeltaCertificateExtension(
//            false,
//            deltaCert);
//        bldr.addExtension(deltaExt);
//
//        X509CertificateHolder chameleonCert = bldr.build(signer);
//
//        assertTrue(chameleonCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(kpB.getPublic())));
//
//        X509CertificateHolder exDeltaCert = DeltaCertificateTool.extractDeltaCertificate(chameleonCert);
//
//        assertTrue(exDeltaCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(kpB.getPublic())));
//    }

    public void testDeltaCertWithExtensions()
        throws Exception
    {
        X500Name subject = new X500Name("CN=Test Subject");

        KeyPairGenerator kpgA = KeyPairGenerator.getInstance("RSA", "BC");

        kpgA.initialize(2048);

        KeyPair kpA = kpgA.generateKeyPair();

        KeyPairGenerator kpgB = KeyPairGenerator.getInstance("EC", "BC");

        kpgB.initialize(new ECNamedCurveGenParameterSpec("P-256"));

        KeyPair kpB = kpgB.generateKeyPair();

        ContentSigner signerA = new JcaContentSignerBuilder("SHA256withRSA").build(kpA.getPrivate());

        Date notBefore = new Date(System.currentTimeMillis() - 5000);
        Date notAfter = new Date(System.currentTimeMillis() + 1000 * 60 * 60);
        X509v3CertificateBuilder bldr = new X509v3CertificateBuilder(
            new X500Name("CN=Chameleon CA 1"),
            BigInteger.valueOf(System.currentTimeMillis()),
            notBefore,
            notAfter,
            subject,
            SubjectPublicKeyInfo.getInstance(kpA.getPublic().getEncoded()));

        bldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        ContentSigner signerB = new JcaContentSignerBuilder("SHA256withECDSA").build(kpB.getPrivate());

        X509v3CertificateBuilder deltaBldr = new X509v3CertificateBuilder(
            new X500Name("CN=Chameleon CA 2"),
            BigInteger.valueOf(System.currentTimeMillis()),
            notBefore,
            notAfter,
            subject,
            SubjectPublicKeyInfo.getInstance(kpB.getPublic().getEncoded()));

        deltaBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        X509CertificateHolder deltaCert = deltaBldr.build(signerB);

        Extension deltaExt = DeltaCertificateTool.makeDeltaCertificateExtension(
            false,
            deltaCert);
        bldr.addExtension(deltaExt);

        X509CertificateHolder chameleonCert = bldr.build(signerA);

        assertTrue(chameleonCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(kpA.getPublic())));

        DeltaCertificateDescriptor deltaCertDesc = DeltaCertificateDescriptor.fromExtensions(chameleonCert.getExtensions());

        assertNull(deltaCertDesc.getExtensions());
        assertNull(deltaCertDesc.getSubject());
        assertNotNull(deltaCertDesc.getIssuer());

        X509CertificateHolder exDeltaCert = DeltaCertificateTool.extractDeltaCertificate(chameleonCert);

        assertTrue(exDeltaCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(kpB.getPublic())));
    }

    public void testCheckCreationAltCertWithDelta()
        throws Exception
    {
        KeyPairGenerator kpgB = KeyPairGenerator.getInstance("EC", "BC");

        kpgB.initialize(new ECNamedCurveGenParameterSpec("P-256"));

        KeyPair kpB = kpgB.generateKeyPair();

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ML-DSA", "BC");

        kpGen.initialize(MLDSAParameterSpec.ml_dsa_44, new SecureRandom());

        KeyPair kp = kpGen.generateKeyPair();

        PrivateKey privKey = kp.getPrivate();
        PublicKey pubKey = kp.getPublic();

        KeyPairGenerator ecKpGen = KeyPairGenerator.getInstance("EC", "BC");

        ecKpGen.initialize(new ECNamedCurveGenParameterSpec("P-256"), new SecureRandom());

        KeyPair ecKp = ecKpGen.generateKeyPair();

        PrivateKey ecPrivKey = ecKp.getPrivate();
        PublicKey ecPubKey = ecKp.getPublic();

        Date notBefore = new Date(System.currentTimeMillis() - 5000);
        Date notAfter = new Date(System.currentTimeMillis() + 1000 * 60 * 60);

        //
        // distinguished name table.
        //
        X500Name issuer = new X500Name("CN=Chameleon Base Issuer");
        X500Name subject = new X500Name("CN=Chameleon Base Subject");

        //
        // create base certificate - version 3
        //
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(ecPrivKey);

        ContentSigner altSigGen = new JcaContentSignerBuilder("ML-DSA-44").setProvider("BC").build(privKey);

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
            issuer,
            BigInteger.valueOf(1),
            notBefore,
            notAfter,
            subject,
            ecPubKey)
            .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
            .addExtension(Extension.subjectAltPublicKeyInfo, false, SubjectAltPublicKeyInfo.getInstance(kp.getPublic().getEncoded()));

        ContentSigner signerB = new JcaContentSignerBuilder("SHA256withECDSA").build(kpB.getPrivate());

        X509v3CertificateBuilder deltaBldr = new X509v3CertificateBuilder(
            new X500Name("CN=Chameleon CA 2"),
            BigInteger.valueOf(System.currentTimeMillis()),
            notBefore,
            notAfter,
            subject,
            SubjectPublicKeyInfo.getInstance(kpB.getPublic().getEncoded()));

        deltaBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
            .addExtension(Extension.subjectAltPublicKeyInfo, false, SubjectAltPublicKeyInfo.getInstance(kp.getPublic().getEncoded()));

        X509CertificateHolder deltaCert = deltaBldr.build(signerB, false, altSigGen);

        assertTrue(deltaCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(kpB.getPublic())));

        Extension deltaExt = DeltaCertificateTool.makeDeltaCertificateExtension(
            false,
            deltaCert);
        certGen.addExtension(deltaExt);

        X509CertificateHolder certHldr = certGen.build(sigGen, false, altSigGen);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHldr);

        //
        // copy certificate           exDeltaCert
        //

        cert.checkValidity(new Date());

        cert.verify(cert.getPublicKey());

        // check encoded works
        cert.getEncoded();

        X509CertificateHolder certHolder = new JcaX509CertificateHolder(cert);

        // assertTrue("alt sig value wrong", certHolder.isAlternativeSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BCPQC").build(pubKey)));

        X509CertificateHolder exDeltaCert = DeltaCertificateTool.extractDeltaCertificate(new X509CertificateHolder(cert.getEncoded()));

        assertTrue(exDeltaCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(kpB.getPublic())));
        assertTrue(exDeltaCert.isAlternativeSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(pubKey)));

        assertTrue(certHldr.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(ecPubKey)));
        assertTrue(certHldr.isAlternativeSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(pubKey)));
    }

    public void testDraftMLDSARoot()
        throws Exception
    {
        X509CertificateHolder baseCert = readCert("ml_dsa_root.pem");

        assertTrue(baseCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(baseCert.getSubjectPublicKeyInfo())));

        X509CertificateHolder deltaCert = DeltaCertificateTool.extractDeltaCertificate(baseCert);

        assertTrue(deltaCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(deltaCert.getSubjectPublicKeyInfo())));

        X509CertificateHolder extCert = readCert("ec_dsa_root.pem");

        assertTrue(extCert.equals(deltaCert));
    }

    public void testDraftMLDSAEndEntity()
        throws Exception
    {
        X509CertificateHolder rootCert = readCert("ml_dsa_root.pem");
        X509CertificateHolder ecRootCert = readCert("ec_dsa_root.pem");
        X509CertificateHolder baseCert = readCert("ec_dsa_ee.pem");

        assertTrue(baseCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(ecRootCert.getSubjectPublicKeyInfo())));

        X509CertificateHolder deltaCert = DeltaCertificateTool.extractDeltaCertificate(baseCert);

        assertTrue(deltaCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(rootCert.getSubjectPublicKeyInfo())));

        X509CertificateHolder extCert = readCert("ml_dsa_ee.pem");

        assertTrue(extCert.equals(deltaCert));
    }

    public void testDraftDualUseEcDsaEndEntity()
        throws Exception
    {
        X509CertificateHolder ecRootCert = readCert("ec_dsa_root.pem");
        X509CertificateHolder baseCert = readCert("ec_dsa_dual_xch_ee.pem");

        assertTrue(baseCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(ecRootCert.getSubjectPublicKeyInfo())));

        X509CertificateHolder deltaCert = DeltaCertificateTool.extractDeltaCertificate(baseCert);

        X509CertificateHolder extCert = readCert("ec_dsa_dual_sig_ee.pem");

        assertTrue(extCert.equals(deltaCert));

        assertTrue(deltaCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(ecRootCert.getSubjectPublicKeyInfo())));
    }

    private static X509CertificateHolder readCert(String name)
        throws Exception
    {
        PEMParser p = new PEMParser(new InputStreamReader(DeltaCertTest.class.getResourceAsStream("delta/" + name)));

        X509CertificateHolder cert = (X509CertificateHolder)p.readObject();

        p.close();

        return cert;
    }
}
