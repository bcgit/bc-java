package org.bouncycastle.mail.smime.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import junit.framework.TestCase;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.crypto.util.JournalingSecureRandom;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mime.smime.SMIMEEnvelopedWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.Streams;

public class JournalingSecureRandomEncryptTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static String _encrDN;
    private static KeyPair _encrKP;
    private static X509Certificate _encrCert;

    private static boolean _initialised = false;

    private static byte[] input_bytes = Base64.decode(
        "This is a story about a coder who didnt know wtf they were doing and"
            + "so every time they tried to do jack shit they just shit themselves "
            + "but it was a happy story inspite of everything because they started "
            + "to learn how to do better");


    private static void init()
        throws Exception

    {
        if (!_initialised)
        {

            if (Security.getProvider("BC") == null)
            {

                Security.addProvider(new BouncyCastleProvider());
            }

            // initialize private key for reading messages here a personal email address is
            _initialised = true;

            // give the path to the certificate of receiver

            _encrDN = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            KeyPairGenerator kpg  = KeyPairGenerator.getInstance("RSA", "BC");
            kpg.initialize(1024, new SecureRandom());
            _encrKP = kpg.generateKeyPair();
            _encrCert = makeCertificate(_encrKP, _encrDN, _encrKP, _encrDN);

        }
    }

    public static X509Certificate makeCertificate(KeyPair subKP, String _subDN, KeyPair issKP, String _issDN)
        throws GeneralSecurityException, IOException, OperatorCreationException
    {

        PublicKey subPub  = subKP.getPublic();
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey  issPub  = issKP.getPublic();

        X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(
            new X500Name(_issDN),
            BigInteger.valueOf(2),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            subPub);

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC");

        X509Certificate _cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(v3CertGen.build(contentSignerBuilder.build(issPriv)));

        _cert.checkValidity(new Date());
        _cert.verify(issPub);

        return _cert;
    }

    /**
     * @throws CertificateEncodingException
     * @throws CMSException
     * @throws IOException
     */
    public void testEncryptFullMessage()
        throws Exception
    {

        init();

        InputStream in_i = new ByteArrayInputStream(input_bytes);

        // output that will contain signed and encrypted content
        OutputStream out_i = new ByteArrayOutputStream();

        //secure random that will be used for both encryptions
        SecureRandom random = new SecureRandom();

        //write encrypted message for a given input a first time using a Secure Random without transcript
        SMIMEEnvelopedWriter.Builder envBldr_i = new SMIMEEnvelopedWriter.Builder();

        JournalingSecureRandom journaling_1 = new JournalingSecureRandom(random);

        JceAsymmetricKeyWrapper wrapper_i = new JceAsymmetricKeyWrapper(_encrCert).setSecureRandom(journaling_1);

        // specify encryption certificate
        JceKeyTransRecipientInfoGenerator key_gen = new JceKeyTransRecipientInfoGenerator(_encrCert, wrapper_i).setProvider(BC);

        envBldr_i.addRecipientInfoGenerator(key_gen);

        OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).setSecureRandom(journaling_1).build();

        AlgorithmIdentifier alg_id = encryptor.getAlgorithmIdentifier();


        SMIMEEnvelopedWriter envWrt = envBldr_i.build(out_i, encryptor);

        OutputStream envOut = envWrt.getContentStream();

        Streams.pipeAll(in_i, envOut);

        envOut.close();

        out_i.close();

        in_i.close();

        //Attempt a second round of encryption, using journaled randomness

        InputStream in_f = new ByteArrayInputStream(input_bytes);

        OutputStream out_f = new ByteArrayOutputStream();

        SMIMEEnvelopedWriter.Builder envBldr_f = new SMIMEEnvelopedWriter.Builder();

        //Create new JournalingSecureRandom using the transcript of the old one
        JournalingSecureRandom journaling_2 = new JournalingSecureRandom(journaling_1.getTranscript(), random);

        JceAsymmetricKeyWrapper wrapper_f = new JceAsymmetricKeyWrapper(_encrCert).setSecureRandom(journaling_2);

        // specify encryption certificate
        envBldr_f.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_encrCert, wrapper_f).setProvider(BC));

        OutputEncryptor encryptor_2 = new JceCMSContentEncryptorBuilder(alg_id).setSecureRandom(journaling_2).build();

        SMIMEEnvelopedWriter envWrt_f = envBldr_f.build(out_f, encryptor_2);

        OutputStream envOut_f = envWrt_f.getContentStream();

        in_i = new ByteArrayInputStream(input_bytes);

        Streams.pipeAll(in_i, envOut_f);

        envOut_f.close();

        in_f.close();

        out_f.close();

        assertTrue(out_i.toString().equals(out_f.toString()));
    }

}
