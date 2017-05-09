package org.bouncycastle.pqc.crypto.test;

import java.io.IOException;
import java.security.SecureRandom;
import java.text.ParseException;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.pqc.crypto.xmss.NullPRNG;
import org.bouncycastle.pqc.crypto.xmss.XMSSMT;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPublicKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;

import junit.framework.TestCase;

/**
 * Test cases for XMSSMTPublicKey class.
 * 
 */
public class XMSSMTPublicKeyTest extends TestCase {

	public void testPublicKeyParsingSHA256() throws IOException, ClassNotFoundException {
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
		assertTrue(XMSSUtil.compareByteArray(publicKey, mt.exportPublicKey()));
	}

	public void testConstructor() {
		XMSSMTParameters params = new XMSSMTParameters(20, 10, new SHA256Digest(), new NullPRNG());
		XMSSMTPublicKeyParameters pk = null;
		try {
			pk = new XMSSMTPublicKeyParameters.Builder(params).build();
		} catch (ParseException ex) {
			ex.printStackTrace();
		}
		byte[] pkByte = pk.toByteArray();
		/* check everything is 0 */
		for (int i = 0; i < pkByte.length; i++) {
			assertEquals(0x00, pkByte[i]);
		}
	}
}
