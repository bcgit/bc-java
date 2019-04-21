package org.bouncycastle.mime.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.test.CMSTestUtil;
import org.bouncycastle.crypto.util.JournaledAlgorithm;
import org.bouncycastle.crypto.util.JournalingSecureRandom;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mime.smime.SMIMEEnvelopedWriter;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.Streams;

/**
 *
 */
public class TestJournalingSecureRandomEncrypt
    extends TestCase
{
    private static final String BC = "BC";

    private static String _encrDN;
    private static KeyPair _encrKP;
    private static X509Certificate _encrCert;

    private static boolean _initialised = false;

    private static byte[] input_bytes = Base64
        .decode("This is a story about a coder who didnt know what they were doing and"
            + "so every time they tried to do anything they just made a mess of it "
            + "but it was a happy story inspite of everything because they started "
            + "to learn how to do better");

    private static void init()
        throws Exception

    {
        if (!_initialised)
        {

            if (Security.getProvider(BC) == null)
            {

                Security.addProvider(new BouncyCastleProvider());
            }

            // initialize private key for reading messages here a personal email address is
            _initialised = true;

            // give the path to the certificate of receiver

            _encrDN = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            _encrKP = CMSTestUtil.makeKeyPair();
            _encrCert = CMSTestUtil.makeCertificate(_encrKP, _encrDN, _encrKP, _encrDN);

        }
    }

    /**
     * Test that two consecutive encryption sessions with reset of parameters in
     * between result in the same output if the parameters are serialized
     *
     * @throws CertificateEncodingException
     * @throws CMSException
     * @throws IOException
     */
    public void testEncryptResetEncryptionSession()
        throws Exception
    {
        init();

        // Create an encryption session from arbitrary JournalingSecureRandom and
        // AlgorithmIdentifier
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        JournalingSecureRandom journaling_1 = new JournalingSecureRandom(new SecureRandom());
        
        ByteArrayOutputStream out_i = encryptWithSession(input_bytes, _encrCert,  CMSAlgorithm.AES128_CBC, journaling_1, bOut);

        // Retrieve session state from seralize temp file
        JournaledAlgorithm retrieved_es = JournaledAlgorithm.getState(new ByteArrayInputStream(bOut.toByteArray()), new SecureRandom());

        // Attempt a second round of encryption, using serialized randomness
        ByteArrayOutputStream out_f = encryptWithSession(input_bytes, _encrCert,  retrieved_es);

        // Assert that the output streams from both encryptions are the same
        assertTrue(
            Arrays.areEqual(
                out_f.toByteArray(),
                out_i.toByteArray()));

    }

    /**
     * NOTE:Run this twice
     *
     * @throws Exception
     */
    public void testEncryptResumeEncryptionSession()
        throws Exception
    {
        init();

        // Create an encryption session from arbitrary JournalingSecureRandom and
        // AlgorithmIdentifier
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        JournalingSecureRandom journaling_1 = new JournalingSecureRandom(new SecureRandom());

        ByteArrayOutputStream out_i = encryptWithSession(input_bytes, _encrCert,  CMSAlgorithm.AES128_CBC, journaling_1, bOut);

        // Retrieve session state from seralize temp file
        JournaledAlgorithm retrieved_es = JournaledAlgorithm.getState(new ByteArrayInputStream(bOut.toByteArray()), new SecureRandom());

        // Attempt a second round of encryption, using serialized randomness
        ByteArrayOutputStream out_f = encryptWithSession(Arrays.concatenate(input_bytes, Strings.toByteArray("extra bytes")), _encrCert,  retrieved_es);

        // Assert that the output streams from both encryptions start the same

        assertTrue(
            Arrays.areEqual(
                Arrays.copyOfRange(out_f.toByteArray(), 0, 821),
                Arrays.copyOfRange(out_i.toByteArray(), 0, 821)));

    }

    public static ByteArrayOutputStream encryptWithSession(byte[] input_bytes, X509Certificate _encrCert, JournaledAlgorithm journaledAlgorithm)
        throws CertificateEncodingException, CMSException, IOException
    {
        InputStream in_i = new ByteArrayInputStream(input_bytes);

        // output that will contain signed and encrypted content
        ByteArrayOutputStream out_i = new ByteArrayOutputStream();

        //write encrypted message for a given input a first time using a Secure Random without transcript
        SMIMEEnvelopedWriter.Builder envBldr_i = new SMIMEEnvelopedWriter.Builder();


        JceAsymmetricKeyWrapper wrapper_i = new JceAsymmetricKeyWrapper(_encrCert).setSecureRandom(
                                                            journaledAlgorithm.getJournalingSecureRandom());

        // specify encryption certificate
        JceKeyTransRecipientInfoGenerator key_gen = new JceKeyTransRecipientInfoGenerator(_encrCert, wrapper_i).setProvider(BC);

        envBldr_i.addRecipientInfoGenerator(key_gen);

        envBldr_i.setBufferSize(20);

        OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(journaledAlgorithm.getAlgorithmIdentifier()).setProvider(BC)
            .setSecureRandom(journaledAlgorithm.getJournalingSecureRandom()).build();

        SMIMEEnvelopedWriter envWrt = envBldr_i.build(out_i, encryptor);

        OutputStream envOut = envWrt.getContentStream();

        Streams.pipeAll(in_i, envOut);

        envOut.close();

        out_i.close();

        in_i.close();

        return out_i;
    }

    public static ByteArrayOutputStream encryptWithSession(byte[] input_bytes, X509Certificate _encrCert, ASN1ObjectIdentifier algorithm, JournalingSecureRandom jsRandom, OutputStream esOut)
        throws CertificateEncodingException, CMSException, IOException
    {
        InputStream in_i = new ByteArrayInputStream(input_bytes);

        // output that will contain signed and encrypted content
        ByteArrayOutputStream out_i = new ByteArrayOutputStream();

        //write encrypted message for a given input a first time using a Secure Random without transcript
        SMIMEEnvelopedWriter.Builder envBldr_i = new SMIMEEnvelopedWriter.Builder();


        JceAsymmetricKeyWrapper wrapper_i = new JceAsymmetricKeyWrapper(_encrCert).setSecureRandom(jsRandom);

        // specify encryption certificate
        JceKeyTransRecipientInfoGenerator key_gen = new JceKeyTransRecipientInfoGenerator(_encrCert, wrapper_i).setProvider(BC);

        envBldr_i.addRecipientInfoGenerator(key_gen);

        envBldr_i.setBufferSize(20);
        
        OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(new AlgorithmIdentifier(algorithm)).setProvider(BC).setSecureRandom(jsRandom).build();

        SMIMEEnvelopedWriter envWrt = envBldr_i.build(out_i, encryptor);

        OutputStream envOut = envWrt.getContentStream();

        // Write the state of the encryption session to the temporary serialize file
        // Note we need to recover algorithm identifier now as in many cases there is no
        // way of initialising an AlgorithmParametersGenerator with our JournalingSecureRandom
        JournaledAlgorithm es = new JournaledAlgorithm(encryptor.getAlgorithmIdentifier(), jsRandom);

        es.storeState(esOut);

        Streams.pipeAll(in_i, envOut);

        envOut.close();

        out_i.close();

        in_i.close();

        return out_i;
    }

}
