package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.DHStandardGroups;
import org.bouncycastle.crypto.engines.CramerShoupCoreEngine;
import org.bouncycastle.crypto.engines.CramerShoupCoreEngine.CramerShoupCiphertext;
import org.bouncycastle.crypto.engines.CramerShoupCoreEngine.CramerShoupCiphertextException;
import org.bouncycastle.crypto.generators.CramerShoupKeyPairGenerator;
import org.bouncycastle.crypto.generators.CramerShoupParametersGenerator;
import org.bouncycastle.crypto.params.CramerShoupKeyGenerationParameters;
import org.bouncycastle.crypto.params.CramerShoupParameters;
import org.bouncycastle.util.test.SimpleTest;

public class CramerShoupTest extends SimpleTest {
	
	private AsymmetricCipherKeyPair keyPair;

	public static void main(String[] args) {
		runTest(new CramerShoupTest());
	}

	@Override
	public String getName() {
		return "CramerShoup";
	}

	@Override
	public void performTest() throws Exception {
		
		BigInteger message = BigInteger.valueOf(123456789);
		
		/*
		 * Encrypt
		 */
		CramerShoupCiphertext ciphertext = encrypt(message);
		
		/*
		 * Decrypt
		 */
		BigInteger m = decrypt(ciphertext);
		
		if (!message.equals(m)){
			fail("decrypted message != original message");
		}
	}

	private BigInteger decrypt(CramerShoupCiphertext ciphertext) {
		
		CramerShoupCoreEngine engine = new CramerShoupCoreEngine();
		engine.init(true, keyPair.getPrivate());
		try {
			BigInteger m = engine.decryptBlock(ciphertext);
			
//			System.out.println(m);
			
			return m;
		} catch (CramerShoupCiphertextException e) {
			e.printStackTrace();
		}
		
		return null;
	}

	private CramerShoupCiphertext encrypt(BigInteger message) {
		CramerShoupKeyPairGenerator kpGen = new CramerShoupKeyPairGenerator();
		CramerShoupParametersGenerator pGen = new CramerShoupParametersGenerator();
		
		pGen.init(2048, 1, new SecureRandom());
		CramerShoupParameters params = pGen.generateParameters(DHStandardGroups.rfc5114_2048_224); // rfc5114_2048_224 rfc3526_2048 
		CramerShoupKeyGenerationParameters param = new CramerShoupKeyGenerationParameters(new SecureRandom(), params);

		kpGen.init(param);
		keyPair = kpGen.generateKeyPair();
		
		CramerShoupCoreEngine engine = new CramerShoupCoreEngine();
		engine.init(false, keyPair.getPublic());
		CramerShoupCiphertext ciphertext = engine.encryptBlock(message);
		
//		System.out.println(ciphertext);
		
		return ciphertext;
	}

}
