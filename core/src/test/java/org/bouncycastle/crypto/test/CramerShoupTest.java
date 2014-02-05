package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.DHStandardGroups;
import org.bouncycastle.crypto.engines.CramerShoupCiphertext;
import org.bouncycastle.crypto.engines.CramerShoupCoreEngine;
import org.bouncycastle.crypto.engines.CramerShoupCoreEngine.CramerShoupCiphertextException;
import org.bouncycastle.crypto.generators.CramerShoupKeyPairGenerator;
import org.bouncycastle.crypto.generators.CramerShoupParametersGenerator;
import org.bouncycastle.crypto.params.CramerShoupKeyGenerationParameters;
import org.bouncycastle.crypto.params.CramerShoupParameters;
import org.bouncycastle.util.BigIntegers;
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

		int i = 0;
		int numTests = 10;
		BigInteger message = BigInteger.ONE;
		
		while (i < numTests){

			message = BigIntegers.createRandomInRange(BigInteger.ONE,
					DHStandardGroups.rfc3526_2048.getP().subtract(BigInteger.ONE),
					new SecureRandom());
			
			BigInteger m1 = encDecTest(message);
			BigInteger m2 = labelledEncDecTest(message, "myRandomLabel");
			BigInteger m3 = encDecEncodingTest(message);
			BigInteger m4 = labelledEncDecEncodingTest(message, "myOtherCoolLabel");
			
			System.out.println(message);
			
			if (!message.equals(m1) || !message.equals(m2) || !message.equals(m3) || !message.equals(m4)){
				fail("decrypted message != original message");
			}
		
			++i;
		}
	}
	
	private BigInteger encDecEncodingTest(BigInteger m){
		CramerShoupCiphertext ciphertext = encrypt(m);
		byte[] c = ciphertext.toByteArray();
		CramerShoupCiphertext decC = new CramerShoupCiphertext(c);
		return decrypt(decC);
	}
	
	private BigInteger labelledEncDecEncodingTest(BigInteger m, String l){
		byte[] c = encrypt(m, l).toByteArray();
		return decrypt(new CramerShoupCiphertext(c), l);
	}
	
	private BigInteger encDecTest(BigInteger m){
		CramerShoupCiphertext c = encrypt(m);
		return decrypt(c);
	}
	
	private BigInteger labelledEncDecTest(BigInteger m, String l){
		CramerShoupCiphertext c = encrypt(m, l);
		return decrypt(c, l);
	}

	
	private BigInteger decrypt(CramerShoupCiphertext ciphertext) {
		return decrypt(ciphertext, null);
	}
	
	private BigInteger decrypt(CramerShoupCiphertext ciphertext, String label) {
		
		CramerShoupCoreEngine engine = new CramerShoupCoreEngine();
		if (label != null)
			engine.init(true, keyPair.getPrivate(), label);
		else
			engine.init(true, keyPair.getPrivate());
		try {
			BigInteger m = engine.decryptBlock(ciphertext);
			
			return m;
		} catch (CramerShoupCiphertextException e) {
			e.printStackTrace();
		}
		
		return null;
	}

	private CramerShoupCiphertext encrypt(BigInteger message) {
		return encrypt(message, null);
	}
	
	private CramerShoupCiphertext encrypt(BigInteger message, String label) {
		CramerShoupKeyPairGenerator kpGen = new CramerShoupKeyPairGenerator();
		CramerShoupParametersGenerator pGen = new CramerShoupParametersGenerator();
		
		pGen.init(2048, 1, new SecureRandom());
		CramerShoupParameters params = pGen.generateParameters(DHStandardGroups.rfc3526_2048);
		CramerShoupKeyGenerationParameters param = new CramerShoupKeyGenerationParameters(new SecureRandom(), params);

		kpGen.init(param);
		keyPair = kpGen.generateKeyPair();
		
		CramerShoupCoreEngine engine = new CramerShoupCoreEngine();
		if (label != null)
			engine.init(false, keyPair.getPublic(), label);
		else
			engine.init(false, keyPair.getPublic());
		
		CramerShoupCiphertext ciphertext = engine.encryptBlock(message);
		
		return ciphertext;
	}

}
