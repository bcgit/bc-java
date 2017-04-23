package org.bouncycastle.pqc.crypto.test;

import java.text.ParseException;

import junit.framework.TestCase;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.pqc.crypto.xmss.NullPRNG;
import org.bouncycastle.pqc.crypto.xmss.XMSSMT;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTSignature;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSReducedSignature;
import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;

/**
 * Test cases for XMSSReducedSignature class.
 * 
 */
public class XMSSReducedSignatureTest extends TestCase {

	public void testSignatureParsingSHA256() {
		XMSSMTParameters params = new XMSSMTParameters(8, 2, new SHA256Digest(), new NullPRNG());
		XMSSMT mt = new XMSSMT(params);
		mt.generateKeys();
		byte[] message = new byte[1024];
		byte[] sig1 = mt.sign(message);
		XMSSMTSignature sig2 = null;
		try {
			sig2 = new XMSSMTSignature.Builder(params).withSignature(sig1).build();
		} catch (ParseException e) {
			e.printStackTrace();
		}
		XMSSReducedSignature reducedSignature1 = sig2.getReducedSignatures().get(0);
		byte[] reducedSignatureBinary = reducedSignature1.toByteArray();
		XMSSReducedSignature reducedSignature2 = null;
		try {
			reducedSignature2 = new XMSSReducedSignature.Builder(new XMSSParameters(4, new SHA256Digest(), new NullPRNG())).withReducedSignature(reducedSignatureBinary).build();
		} catch (ParseException e) {
			e.printStackTrace();
		}
		assertTrue(XMSSUtil.compareByteArray(reducedSignatureBinary, reducedSignature2.toByteArray()));
	}

	public void testSignatureParsingSHA512() {
		XMSSMTParameters params = new XMSSMTParameters(4, 2, new SHA512Digest(), new NullPRNG());
		XMSSMT mt = new XMSSMT(params);
		mt.generateKeys();
		byte[] message = new byte[1024];
		byte[] sig1 = mt.sign(message);
		XMSSMTSignature sig2 = null;
		try {
			sig2 = new XMSSMTSignature.Builder(params).withSignature(sig1).build();
		} catch (ParseException e) {
			e.printStackTrace();
		}
		XMSSReducedSignature reducedSignature1 = sig2.getReducedSignatures().get(0);
		byte[] reducedSignatureBinary = reducedSignature1.toByteArray();
		XMSSReducedSignature reducedSignature2 = null;
		try {
			reducedSignature2 = new XMSSReducedSignature.Builder(new XMSSParameters(2, new SHA512Digest(), new NullPRNG())).withReducedSignature(reducedSignatureBinary).build();
		} catch (ParseException e) {
			e.printStackTrace();
		}
		assertTrue(XMSSUtil.compareByteArray(reducedSignatureBinary, reducedSignature2.toByteArray()));
	}

	public void testConstructor() {
		XMSSReducedSignature sig = null;
		try {
			sig = new XMSSReducedSignature.Builder(new XMSSParameters(4, new SHA512Digest(), new NullPRNG())).build();
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
