package test;

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

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.crypto.util.JournalingSecureRandom;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.test.CMSTestUtil;
import org.bouncycastle.mime.smime.SMIMEEnvelopedWriter;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;
import org.bouncycastle.util.encoders.Base64;

import junit.framework.TestCase;

/**
 * License: https://www.gnu.org/licenses/agpl-3.0.en.html and
 * https://www.my-d.org/ProfitContributionAgreement
 *
 */
public class JournalingSecureRandomEncryptTest extends TestCase {
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


	private static void init() throws Exception

	{
		if (!_initialised) {

			if (Security.getProvider("BC") == null) {

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
 * 
 * @throws CertificateEncodingException
 * @throws CMSException
 * @throws IOException
 */
	public void testEncryptFullMessage()throws Exception {
		
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

		in_i.transferTo(envOut);

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

		in_f.transferTo(envOut_f);
		
		envOut_f.close();
		
		in_f.close();
		
		out_f.close();

		assert(out_i.toString().equals(out_f.toString()));
		
	
	}

}
