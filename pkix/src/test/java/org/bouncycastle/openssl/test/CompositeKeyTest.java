package org.bouncycastle.openssl.test;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Date;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * Tests from: https://datatracker.ietf.org/doc/draft-ounsworth-pq-composite-keys/
 *
 * @deprecated These are old acceptance tests once used for inter-op testing.
 */
public class CompositeKeyTest
    extends TestCase
{
    private static final String genPubKey =
            "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBmDAMBgpghkgBhvprUAQBA4IBhgAwggGBMFkwEwYHKoZIzj0CAQYIKoZIzj0D\n"+
            "AQcDQgAExGPhrnuSG/fGyw1FN+l5h4p4AGRQCS0LBXnBO+djhcI6qnF2TvrQEaIY\n"+
            "GGpQT5wHS+7y5iJJ+dE5qjxcv8loRDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\n"+
            "AQoCggEBANsVQK1fcLQObL4ZYtczWbObECAFSsng0OLpRTPr9VGV3SsS/VoMRZqX\n"+
            "F+sszz6I2UcFTaMF9CwNRbWLuIBczzuhbHSjn65OuoN+Om2wsPo+okw46RTekB4a\n"+
            "d9QQvYRVzPlILUQ8NvZ4W0BKLviXTXWIggjtp/Y1pKRHKz8n35J6OmFWz4TKGNth\n"+
            "n87D28kmdwQYH5NLsDePHbfdw3AyLrPvQLlQw/hRPz/9Txf7yi9Djg9HtJ88ES6+\n"+
            "ZbfE1ZHxLYLSDt25tSL8A2pMuGMD3P81nYWO+gJ0vYV2WcRpXHRkjmliGqiCg4eB\n"+
            "mC4//tm0J4r9Ll8b/pp6xyOMI7jppVUCAwEAAQ==\n"+
            "-----END PUBLIC KEY-----\n";

    private static final String genPrivKey =
            "-----BEGIN PRIVATE KEY-----\n"+
            "MIIFHgIBADAMBgpghkgBhvprUAQBBIIFCTCCBQUwQQIBADATBgcqhkjOPQIBBggq\n"+
            "hkjOPQMBBwQnMCUCAQEEICN0ihCcgg5n8ALtk9tkQZqg/WLEm5NefMi/kdN06Z9u\n"+
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDbFUCtX3C0Dmy+\n"+
            "GWLXM1mzmxAgBUrJ4NDi6UUz6/VRld0rEv1aDEWalxfrLM8+iNlHBU2jBfQsDUW1\n"+
            "i7iAXM87oWx0o5+uTrqDfjptsLD6PqJMOOkU3pAeGnfUEL2EVcz5SC1EPDb2eFtA\n"+
            "Si74l011iIII7af2NaSkRys/J9+SejphVs+EyhjbYZ/Ow9vJJncEGB+TS7A3jx23\n"+
            "3cNwMi6z70C5UMP4UT8//U8X+8ovQ44PR7SfPBEuvmW3xNWR8S2C0g7dubUi/ANq\n"+
            "TLhjA9z/NZ2FjvoCdL2FdlnEaVx0ZI5pYhqogoOHgZguP/7ZtCeK/S5fG/6aescj\n"+
            "jCO46aVVAgMBAAECggEAFtT6LpdZuYofTxh6Mo9Jc+xfG9cxWiSx4FQLQEQBBwWl\n"+
            "TQ3nlXDd+CRy+7Fpz8yXSE2HL8w5DDY945OyIL6LYl2KXgWHaLUPvxByqmfVqd7J\n"+
            "L0RnFiOzxU9g2Zr9BUOj3v7kqM3VtI4KhIK2rnWmPu+BDckmzgP9Kpm4KhbPuAYP\n"+
            "iqUZSkxpSUsd5ALLsk9b0xjR7UEYkEpV2/vORwieEhOmPLzuXh+Px0yavkazT/vU\n"+
            "+h/rDSoLQn7v4fVsQgNdOaaOG/gHemGuuiLPJJlX5ZZ6mmsIaEjz+MNk0aJDH2po\n"+
            "KbAr4B709dTsnYgv7YtkEfSyOeMEdhMiswI1c9FpwQKBgQD6kdHmHCoeWNNvlqxU\n"+
            "v57e7ZDAXDA6WcfrypcsF0l72rI3J8oOPmFaNaCmwIH/Icz+Zy7fr2IYxVjyDjCa\n"+
            "zi8qTnj2ZNds71hUYOcq60u0TcSVrtocA4HW7NoWJqK5thNlNaa1M358cYBopGoN\n"+
            "ocS9yf10q2MBZtpF0fc5PbFf+QKBgQDf1L4cezoebbNTaN4KoapycHXxKozP2GwI\n"+
            "r15YRYjt0ZpHstdUPABQuwlL9CuL+5Q17VRiM81cUVNfFsBzKIXYb/PBC5UD+DmR\n"+
            "qGlT6v6uUWY6jifUgEjfyPxO0oJ3M6cChHR/TvpkT5SyaEwHpIH7IeXbMFcS5m4G\n"+
            "mSNBECO/PQKBgCD0CoHT1Go3Tl9PloxywwcYgT/7H9CcvCEzfJws19o1EdkVH4qu\n"+
            "A4mkoeMsUCxompgeo9iBLUqKsb7rxNKnKSbMOTZWXsqR07ENKXnIhiVJUQBKhZ7H\n"+
            "i0zjy268WAxKeNSHsMwF4K2nE7cvYE84pjI7nVy5qYSmrTAfg/8AMRKpAoGBAN/G\n"+
            "wN6WsE9Vm5BLapo0cMUC/FdFFAyEMdYpBei4dCJXiKgf+7miVypfI/dEwPitZ8rW\n"+
            "YKPhaHHgeLq7c2JuZAo0Ov2IR831MBEYz1zvtvmuNcda8iU4sCLTvLRNL9Re1pzk\n"+
            "sdfJrPn2uhH3xfNqG+1oQXZ3CMbDi8Ka/a0Bpst9AoGBAPR4p6WN0aoZlosyT6NI\n"+
            "4mqzNvLE4KBasmfoMmTJih7qCP3X4pqdgiI0SjsQQG/+utHLoJARwzhWHOZf1JKk\n"+
            "D8lSJH02cp/Znrjn5wPpfYKLphJBiKSPwyIjuFwcR1ck84ONeYq421NDqf7lXbvx\n"+
            "oMqjTPagXUpzHvwluDjtSi8+\n"+
            "-----END PRIVATE KEY-----\n";

    private static final String expPubKey =
            "-----BEGIN PUBLIC KEY-----\n"+
            "MIIBkTAFBgMqAwQDggGGADCCAYEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATE\n"+
            "Y+Gue5Ib98bLDUU36XmHingAZFAJLQsFecE752OFwjqqcXZO+tARohgYalBPnAdL\n"+
            "7vLmIkn50TmqPFy/yWhEMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n"+
            "2xVArV9wtA5svhli1zNZs5sQIAVKyeDQ4ulFM+v1UZXdKxL9WgxFmpcX6yzPPojZ\n"+
            "RwVNowX0LA1FtYu4gFzPO6FsdKOfrk66g346bbCw+j6iTDjpFN6QHhp31BC9hFXM\n"+
            "+UgtRDw29nhbQEou+JdNdYiCCO2n9jWkpEcrPyffkno6YVbPhMoY22GfzsPbySZ3\n"+
            "BBgfk0uwN48dt93DcDIus+9AuVDD+FE/P/1PF/vKL0OOD0e0nzwRLr5lt8TVkfEt\n"+
            "gtIO3bm1IvwDaky4YwPc/zWdhY76AnS9hXZZxGlcdGSOaWIaqIKDh4GYLj/+2bQn\n"+
            "iv0uXxv+mnrHI4wjuOmlVQIDAQAB\n"+
            "-----END PUBLIC KEY-----\n";

    private static final String expPrivKey = 
               "-----BEGIN PRIVATE KEY-----\n"+
               "MIIFFwIBADAFBgMqAwQEggUJMIIFBTBBAgEAMBMGByqGSM49AgEGCCqGSM49AwEH\n"+
               "BCcwJQIBAQQgI3SKEJyCDmfwAu2T22RBmqD9YsSbk158yL+R03Tpn24wggS+AgEA\n"+
               "MA0GCSqGSIb3DQEBAQUABIIEqDCCBKQCAQACggEBANsVQK1fcLQObL4ZYtczWbOb\n"+
               "ECAFSsng0OLpRTPr9VGV3SsS/VoMRZqXF+sszz6I2UcFTaMF9CwNRbWLuIBczzuh\n"+
               "bHSjn65OuoN+Om2wsPo+okw46RTekB4ad9QQvYRVzPlILUQ8NvZ4W0BKLviXTXWI\n"+
               "ggjtp/Y1pKRHKz8n35J6OmFWz4TKGNthn87D28kmdwQYH5NLsDePHbfdw3AyLrPv\n"+
               "QLlQw/hRPz/9Txf7yi9Djg9HtJ88ES6+ZbfE1ZHxLYLSDt25tSL8A2pMuGMD3P81\n"+
               "nYWO+gJ0vYV2WcRpXHRkjmliGqiCg4eBmC4//tm0J4r9Ll8b/pp6xyOMI7jppVUC\n"+
               "AwEAAQKCAQAW1Poul1m5ih9PGHoyj0lz7F8b1zFaJLHgVAtARAEHBaVNDeeVcN34\n"+
               "JHL7sWnPzJdITYcvzDkMNj3jk7IgvotiXYpeBYdotQ+/EHKqZ9Wp3skvRGcWI7PF\n"+
               "T2DZmv0FQ6Pe/uSozdW0jgqEgraudaY+74ENySbOA/0qmbgqFs+4Bg+KpRlKTGlJ\n"+
               "Sx3kAsuyT1vTGNHtQRiQSlXb+85HCJ4SE6Y8vO5eH4/HTJq+RrNP+9T6H+sNKgtC\n"+
               "fu/h9WxCA105po4b+Ad6Ya66Is8kmVfllnqaawhoSPP4w2TRokMfamgpsCvgHvT1\n"+
               "1OydiC/ti2QR9LI54wR2EyKzAjVz0WnBAoGBAPqR0eYcKh5Y02+WrFS/nt7tkMBc\n"+
               "MDpZx+vKlywXSXvasjcnyg4+YVo1oKbAgf8hzP5nLt+vYhjFWPIOMJrOLypOePZk\n"+
               "12zvWFRg5yrrS7RNxJWu2hwDgdbs2hYmorm2E2U1prUzfnxxgGikag2hxL3J/XSr\n"+
               "YwFm2kXR9zk9sV/5AoGBAN/Uvhx7Oh5ts1No3gqhqnJwdfEqjM/YbAivXlhFiO3R\n"+
               "mkey11Q8AFC7CUv0K4v7lDXtVGIzzVxRU18WwHMohdhv88ELlQP4OZGoaVPq/q5R\n"+
               "ZjqOJ9SASN/I/E7SgnczpwKEdH9O+mRPlLJoTAekgfsh5dswVxLmbgaZI0EQI789\n"+
               "AoGAIPQKgdPUajdOX0+WjHLDBxiBP/sf0Jy8ITN8nCzX2jUR2RUfiq4DiaSh4yxQ\n"+
               "LGiamB6j2IEtSoqxvuvE0qcpJsw5NlZeypHTsQ0peciGJUlRAEqFnseLTOPLbrxY\n"+
               "DEp41IewzAXgracTty9gTzimMjudXLmphKatMB+D/wAxEqkCgYEA38bA3pawT1Wb\n"+
               "kEtqmjRwxQL8V0UUDIQx1ikF6Lh0IleIqB/7uaJXKl8j90TA+K1nytZgo+FoceB4\n"+
               "urtzYm5kCjQ6/YhHzfUwERjPXO+2+a41x1ryJTiwItO8tE0v1F7WnOSx18ms+fa6\n"+
               "EffF82ob7WhBdncIxsOLwpr9rQGmy30CgYEA9HinpY3RqhmWizJPo0jiarM28sTg\n"+
               "oFqyZ+gyZMmKHuoI/dfimp2CIjRKOxBAb/660cugkBHDOFYc5l/UkqQPyVIkfTZy\n"+
               "n9meuOfnA+l9goumEkGIpI/DIiO4XBxHVyTzg415irjbU0Op/uVdu/GgyqNM9qBd\n"+
               "SnMe/CW4OO1KLz4=\n"+
               "-----END PRIVATE KEY-----\n";

    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testGenericCompositeKey()
        throws Exception
    {
        PEMParser pemParser = new PEMParser(new StringReader(genPubKey));

        SubjectPublicKeyInfo pubKey = (SubjectPublicKeyInfo)pemParser.readObject();

        pemParser = new PEMParser(new StringReader(genPrivKey));

        PrivateKeyInfo privKey = (PrivateKeyInfo)pemParser.readObject();
    }

    public void testExplicitCompositeKey()
        throws Exception
    {
        PEMParser pemParser = new PEMParser(new StringReader(expPubKey));

        SubjectPublicKeyInfo pubKey = (SubjectPublicKeyInfo)pemParser.readObject();

        pemParser = new PEMParser(new StringReader(genPrivKey));

        PrivateKeyInfo privKey = (PrivateKeyInfo)pemParser.readObject();
    }

    public void testCompositeSignatureStripping()
        throws Exception
    {
        // CVE-2026-5588 follow-up: the legacy id_alg_composite ContentVerifier
        // accepted a composite signature truncated to a single verifiable
        // component. The empty-sequence case was fixed; an under-length sequence
        // still passed. A composite signature MUST carry every component.
        //
        // Legacy composite signature *creation* via JcaContentSignerBuilder has
        // since been removed (verification is unaffected), so the genuine 2-of-2
        // signature below is built directly from two raw java.security.Signature
        // instances rather than through the builder.
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC", "BC");
        ecKpg.initialize(new ECNamedCurveGenParameterSpec("P-256"));
        KeyPair ecKp = ecKpg.generateKeyPair();

        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA", "BC");
        rsaKpg.initialize(new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4));
        KeyPair rsaKp = rsaKpg.generateKeyPair();

        CompositePublicKey compPub = new CompositePublicKey(ecKp.getPublic(), rsaKp.getPublic());

        // component 0 = ECDSA, component 1 = RSA
        final DefaultSignatureAlgorithmIdentifierFinder algFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        final AlgorithmIdentifier compSigAlgId = new AlgorithmIdentifier(
            MiscObjectIdentifiers.id_alg_composite,
            new DERSequence(algFinder.find("SHA256withECDSA"), algFinder.find("SHA256withRSA")));
        final Signature ecSig = Signature.getInstance("SHA256withECDSA", "BC");
        ecSig.initSign(ecKp.getPrivate());
        final Signature rsaSig = Signature.getInstance("SHA256withRSA", "BC");
        rsaSig.initSign(rsaKp.getPrivate());

        ContentSigner sigGen = new ContentSigner()
        {
            private final ByteArrayOutputStream bOut = new ByteArrayOutputStream();

            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return compSigAlgId;
            }

            public OutputStream getOutputStream()
            {
                return bOut;
            }

            public byte[] getSignature()
            {
                try
                {
                    byte[] tbs = bOut.toByteArray();
                    ecSig.update(tbs);
                    rsaSig.update(tbs);
                    return new DERSequence(new DERBitString(ecSig.sign()), new DERBitString(rsaSig.sign()))
                        .getEncoded(ASN1Encoding.DER);
                }
                catch (GeneralSecurityException e)
                {
                    throw new RuntimeException(e);
                }
                catch (IOException e)
                {
                    throw new RuntimeException(e);
                }
            }
        };

        X500Name name = new X500Name("CN=Composite Strip Test");
        X509CertificateHolder certHldr = new JcaX509v3CertificateBuilder(
            name, BigInteger.valueOf(1),
            new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000),
            name, compPub).build(sigGen);

        // the genuine 2-of-2 composite signature verifies
        assertTrue("genuine composite signature should verify",
            certHldr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(compPub)));

        AlgorithmIdentifier sigAlgId = certHldr.getSignatureAlgorithm();
        byte[] tbs = certHldr.toASN1Structure().getTBSCertificate().getEncoded(ASN1Encoding.DER);
        ASN1Sequence sigSeq = ASN1Sequence.getInstance(certHldr.getSignature());
        assertTrue("expected a two-component composite signature", sigSeq.size() == 2);

        // strip the RSA component, leaving only the (genuine) ECDSA component
        byte[] strippedSig = new DERSequence(sigSeq.getObjectAt(0)).getEncoded(ASN1Encoding.DER);

        ContentVerifier cv = new JcaContentVerifierProviderBuilder().build(compPub).get(sigAlgId);
        OutputStream sOut = cv.getOutputStream();
        sOut.write(tbs);
        sOut.close();

        assertFalse("composite signature stripped of a component must not verify", cv.verify(strippedSig));
    }

    public void testModernCompositeKeyRejectsLegacyCompositeSignature()
        throws Exception
    {
        // A modern fixed-algorithm composite public key (id_MLDSA44_Ed25519_SHA512, two
        // components) must never be checked via the legacy generic id_alg_composite signature
        // format. That format trusts an attacker-controlled AlgorithmIdentifier parameter
        // sequence to say both how many components to check and which key indexes to check them
        // against - accepting it against a modern key let a one-component (ML-DSA-44 only)
        // legacy-shaped signature satisfy verification of the two-component modern key, silently
        // dropping the Ed25519 check the composite identity exists to require.
        KeyPairGenerator mlDsaKpg = KeyPairGenerator.getInstance("ML-DSA", "BC");
        mlDsaKpg.initialize(MLDSAParameterSpec.ml_dsa_44);
        KeyPair mlDsaKp = mlDsaKpg.generateKeyPair();

        KeyPairGenerator edKpg = KeyPairGenerator.getInstance("Ed25519", "BC");
        KeyPair edKp = edKpg.generateKeyPair();

        CompositePublicKey modernPub = new CompositePublicKey(
            IANAObjectIdentifiers.id_MLDSA44_Ed25519_SHA512, mlDsaKp.getPublic(), edKp.getPublic());

        byte[] message = Strings.toByteArray("modern composite key, legacy signature downgrade regression test");

        Signature mlDsaSigner = Signature.getInstance("ML-DSA-44", "BC");
        mlDsaSigner.initSign(mlDsaKp.getPrivate());
        mlDsaSigner.update(message);
        byte[] mlDsaSignature = mlDsaSigner.sign();

        // a one-component legacy AlgorithmIdentifier/signature pair naming only ML-DSA-44
        AlgorithmIdentifier oneComponentLegacyAlgId = new AlgorithmIdentifier(
            MiscObjectIdentifiers.id_alg_composite,
            new DERSequence(new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_44)));
        byte[] oneComponentLegacySignature = new DERSequence(new DERBitString(mlDsaSignature)).getEncoded(ASN1Encoding.DER);

        ContentVerifierProvider provider = new JcaContentVerifierProviderBuilder().setProvider("BC").build(modernPub);

        try
        {
            ContentVerifier cv = provider.get(oneComponentLegacyAlgId);
            OutputStream sOut = cv.getOutputStream();
            sOut.write(message);
            sOut.close();

            assertFalse("legacy one-component signature must not verify a modern composite key",
                cv.verify(oneComponentLegacySignature));
        }
        catch (OperatorCreationException e)
        {
            // rejecting the algorithm/key combination outright is the expected, stronger response
        }

        // the modern key's own algorithm must still verify a genuine two-component signature
        CompositePrivateKey modernPriv = new CompositePrivateKey(
            IANAObjectIdentifiers.id_MLDSA44_Ed25519_SHA512, mlDsaKp.getPrivate(), edKp.getPrivate());

        Signature modernSigner = Signature.getInstance("MLDSA44-Ed25519-SHA512", "BC");
        modernSigner.initSign(modernPriv);
        modernSigner.update(message);
        byte[] genuineModernSignature = modernSigner.sign();

        Signature modernVerifier = Signature.getInstance("MLDSA44-Ed25519-SHA512", "BC");
        modernVerifier.initVerify(modernPub);
        modernVerifier.update(message);
        assertTrue("genuine two-component modern composite signature should verify",
            modernVerifier.verify(genuineModernSignature));
    }

    public void testLegacyCompositeKeyRejectsForgedShortLegacySignature()
        throws Exception
    {
        // Broader than testModernCompositeKeyRejectsLegacyCompositeSignature: even a PURELY
        // legacy composite key (id_composite_key, no modern key involved at all) never actually
        // required every component to validate. The CVE-2026-5588 follow-up's sigSeq.size() !=
        // sigs.length check only confirms a signature is self-consistent with its own declared
        // shape - it never compares that shape with the trusted key's real component count. So
        // it catches *stripping* an honest two-component signature down to one (see
        // testCompositeSignatureStripping, which starts from a genuine signature and truncates
        // the encoded bytes) but not an attacker who holds only one real component's private key
        // and constructs a self-consistent one-component AlgorithmIdentifier/signature pair from
        // scratch, matching each other but not the key. Confirmed experimentally: disabling just
        // the keySeq.size() != pubKeys.size() check (leaving the legacy-key-OID check intact,
        // since the key here already is legacy) makes this accept.
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC", "BC");
        ecKpg.initialize(new ECNamedCurveGenParameterSpec("P-256"));
        KeyPair ecKp = ecKpg.generateKeyPair();

        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA", "BC");
        rsaKpg.initialize(new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4));
        KeyPair rsaKp = rsaKpg.generateKeyPair();

        // a purely legacy two-component composite key - both components real, no modern OID
        CompositePublicKey legacyCompPub = new CompositePublicKey(ecKp.getPublic(), rsaKp.getPublic());

        byte[] message = Strings.toByteArray("legacy composite key, forged one-component signature regression test");

        // only the EC component's signing capability is used - as if that were the only key
        // an attacker (or a compromised single-algorithm signing service) actually had
        Signature ecSigner = Signature.getInstance("SHA256withECDSA", "BC");
        ecSigner.initSign(ecKp.getPrivate());
        ecSigner.update(message);
        byte[] ecSignature = ecSigner.sign();

        // a freshly forged one-component legacy AlgorithmIdentifier/signature pair, naming only
        // the EC component - not derived by stripping a genuine two-component signature
        DefaultSignatureAlgorithmIdentifierFinder algFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        AlgorithmIdentifier oneComponentLegacyAlgId = new AlgorithmIdentifier(
            MiscObjectIdentifiers.id_alg_composite,
            new DERSequence(algFinder.find("SHA256withECDSA")));
        byte[] oneComponentLegacySignature = new DERSequence(new DERBitString(ecSignature)).getEncoded(ASN1Encoding.DER);

        ContentVerifierProvider provider = new JcaContentVerifierProviderBuilder().setProvider("BC").build(legacyCompPub);

        try
        {
            ContentVerifier cv = provider.get(oneComponentLegacyAlgId);
            OutputStream sOut = cv.getOutputStream();
            sOut.write(message);
            sOut.close();

            assertFalse("forged one-component legacy signature must not verify a two-component legacy composite key",
                cv.verify(oneComponentLegacySignature));
        }
        catch (OperatorCreationException e)
        {
            // rejecting the component-count mismatch outright is the expected, stronger response
        }
    }

    public void testMLDSA44andP256()
        throws Exception
    {
        //
        // set up the keys
        //
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC", "BC");

        ecKpg.initialize(new ECNamedCurveGenParameterSpec("P-256"));

        KeyPair ecKp = ecKpg.generateKeyPair();

        PrivateKey ecPriv = ecKp.getPrivate();
        PublicKey ecPub = ecKp.getPublic();

        KeyPairGenerator rmldsaKpg = KeyPairGenerator.getInstance("ML-DSA-44", "BC");

        KeyPair mldsaKp = rmldsaKpg.generateKeyPair();

        PrivateKey mldsaPriv = mldsaKp.getPrivate();
        PublicKey mldsaPub = mldsaKp.getPublic();

        CompositePrivateKey mlecPriv = new CompositePrivateKey(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256, mldsaPriv, ecPriv);

        StringWriter sWrt = new StringWriter();
        JcaPEMWriter pWrt = new JcaPEMWriter(sWrt);

        pWrt.writeObject(mlecPriv);

        pWrt.close();

        CompositePublicKey mlecPub = new CompositePublicKey(mldsaPub, ecPub);

        pWrt = new JcaPEMWriter(sWrt);

        pWrt.writeObject(mlecPub);

        pWrt.close();

        PEMParser pPrs = new PEMParser(new StringReader(sWrt.toString()));

        JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter().setProvider("BC");
        CompositePrivateKey prKey = (CompositePrivateKey)keyConverter.getPrivateKey((PrivateKeyInfo)pPrs.readObject());

        CompositePublicKey puKey = (CompositePublicKey)keyConverter.getPublicKey((SubjectPublicKeyInfo)pPrs.readObject());
    }

    public void testMLDSA44andEd25519()
        throws Exception
    {
        //
        // set up the keys
        //
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("ED25519", "BC");

        KeyPair ecKp = ecKpg.generateKeyPair();

        PrivateKey ecPriv = ecKp.getPrivate();
        PublicKey ecPub = ecKp.getPublic();

        KeyPairGenerator rmldsaKpg = KeyPairGenerator.getInstance("ML-DSA-44", "BC");

        KeyPair mldsaKp = rmldsaKpg.generateKeyPair();

        PrivateKey mldsaPriv = mldsaKp.getPrivate();
        PublicKey mldsaPub = mldsaKp.getPublic();

        CompositePrivateKey mlecPriv = new CompositePrivateKey(IANAObjectIdentifiers.id_MLDSA44_Ed25519_SHA512, mldsaPriv, ecPriv);

        StringWriter sWrt = new StringWriter();
        JcaPEMWriter pWrt = new JcaPEMWriter(sWrt);

        pWrt.writeObject(mlecPriv);

        pWrt.close();

        CompositePublicKey mlecPub = new CompositePublicKey(mldsaPub, ecPub);

        pWrt = new JcaPEMWriter(sWrt);

        pWrt.writeObject(mlecPub);

        pWrt.close();

        PEMParser pPrs = new PEMParser(new StringReader(sWrt.toString()));

        JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter().setProvider("BC");
        CompositePrivateKey prKey = (CompositePrivateKey)keyConverter.getPrivateKey((PrivateKeyInfo)pPrs.readObject());

        CompositePublicKey puKey = (CompositePublicKey)keyConverter.getPublicKey((SubjectPublicKeyInfo)pPrs.readObject());
    }

    public void testMLDSA87andEd448()
        throws Exception
    {
        //
        // set up the keys
        //
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("ED448", "BC");

        KeyPair ecKp = ecKpg.generateKeyPair();

        PrivateKey ecPriv = ecKp.getPrivate();
        PublicKey ecPub = ecKp.getPublic();

        KeyPairGenerator rmldsaKpg = KeyPairGenerator.getInstance("ML-DSA-87", "BC");

        KeyPair mldsaKp = rmldsaKpg.generateKeyPair();

        PrivateKey mldsaPriv = mldsaKp.getPrivate();
        PublicKey mldsaPub = mldsaKp.getPublic();

        CompositePrivateKey mlecPriv = new CompositePrivateKey(IANAObjectIdentifiers.id_MLDSA87_Ed448_SHAKE256, mldsaPriv, ecPriv);

        StringWriter sWrt = new StringWriter();
        JcaPEMWriter pWrt = new JcaPEMWriter(sWrt);

        pWrt.writeObject(mlecPriv);

        pWrt.close();

        CompositePublicKey mlecPub = new CompositePublicKey(mldsaPub, ecPub);

        pWrt = new JcaPEMWriter(sWrt);

        pWrt.writeObject(mlecPub);

        pWrt.close();

        PEMParser pPrs = new PEMParser(new StringReader(sWrt.toString()));

        JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter().setProvider("BC");
        CompositePrivateKey prKey = (CompositePrivateKey)keyConverter.getPrivateKey((PrivateKeyInfo)pPrs.readObject());

        CompositePublicKey puKey = (CompositePublicKey)keyConverter.getPublicKey((SubjectPublicKeyInfo)pPrs.readObject());
    }

    private static void doOutput(String fileName, String contents)
        throws IOException
    {
        FileOutputStream fOut = new FileOutputStream(fileName);
        fOut.write(Strings.toByteArray(contents));
        fOut.close();
    }
}
