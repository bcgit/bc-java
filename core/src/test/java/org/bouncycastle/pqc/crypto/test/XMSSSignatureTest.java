package org.bouncycastle.pqc.crypto.test;

import java.text.ParseException;

import junit.framework.TestCase;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.pqc.crypto.xmss.NullPRNG;
import org.bouncycastle.pqc.crypto.xmss.XMSS;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSSignature;
import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;

/**
 * Test cases for XMSSSignature class.
 * 
 */
public class XMSSSignatureTest extends TestCase {

	public void testSignatureParsingSHA256() {
		XMSSParameters params = new XMSSParameters(10, new SHA256Digest(), new NullPRNG());
		XMSS xmss = new XMSS(params);
		xmss.generateKeys();
		byte[] message = new byte[1024];
		byte[] sig1 = xmss.sign(message);
		XMSSSignature sig2 = null;
		try {
			sig2 = new XMSSSignature.Builder(params).withSignature(sig1).build();
		} catch (ParseException ex) {
			ex.printStackTrace();
			fail();
		}
		byte[] sig3 = sig2.toByteArray();
		assertEquals(true, XMSSUtil.compareByteArray(sig1, sig3));
	}

	public void testSignatureParsingSHA512() {
		XMSSParameters params = new XMSSParameters(10, new SHA512Digest(), new NullPRNG());
		XMSS xmss = new XMSS(params);
		xmss.generateKeys();
		byte[] message = new byte[1024];
		byte[] sig1 = xmss.sign(message);
		XMSSSignature sig2 = null;
		try {
			sig2 = new XMSSSignature.Builder(params).withSignature(sig1).build();
		} catch (ParseException ex) {
			ex.printStackTrace();
			fail();
		}
		byte[] sig3 = sig2.toByteArray();
		assertEquals(true, XMSSUtil.compareByteArray(sig1, sig3));
	}

	public void testConstructor() {
		XMSSParameters params = new XMSSParameters(10, new SHA256Digest(), new NullPRNG());
		XMSSSignature sig = null;
		try {
			sig = new XMSSSignature.Builder(params).build();
		} catch (ParseException ex) {
			ex.printStackTrace();
		}
		byte[] sigByte = sig.toByteArray();
		/* check everything is 0 */
		for (int i = 0; i < sigByte.length; i++) {
			assertEquals(0x00, sigByte[i]);
		}
	}
}
