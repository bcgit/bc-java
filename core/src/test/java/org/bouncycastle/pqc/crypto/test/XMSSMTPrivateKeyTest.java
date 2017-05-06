package org.bouncycastle.pqc.crypto.test;

import java.io.IOException;
import java.security.SecureRandom;
import java.text.ParseException;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.pqc.crypto.xmss.XMSSMT;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;

import junit.framework.TestCase;

/**
 * Test cases for XMSSMTPrivateKey class.
 * 
 */
public class XMSSMTPrivateKeyTest extends TestCase {

	public void testPrivateKeyParsingSHA256() throws IOException, ClassNotFoundException {
		XMSSMTParameters params = new XMSSMTParameters(20, 10, new SHA256Digest(), new SecureRandom());
		XMSSMT mt = new XMSSMT(params);
		mt.generateKeys();
		byte[] privateKey = mt.exportPrivateKey();
		byte[] publicKey = mt.exportPublicKey();
		try {
			mt.importState(privateKey, publicKey);
		} catch (ParseException e) {
			e.printStackTrace();
		}
		assertTrue(XMSSUtil.compareByteArray(privateKey, mt.exportPrivateKey()));
	}
}
