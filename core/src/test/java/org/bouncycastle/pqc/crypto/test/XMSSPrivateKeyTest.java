package org.bouncycastle.pqc.crypto.test;

import java.io.IOException;
import java.text.ParseException;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.pqc.crypto.xmss.NullPRNG;
import org.bouncycastle.pqc.crypto.xmss.XMSS;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;

import junit.framework.TestCase;

/**
 * Test cases for XMSSPrivateKey class.
 * 
 */
public class XMSSPrivateKeyTest extends TestCase {

	public void testPrivateKeyParsing() throws ClassNotFoundException, IOException {
		XMSSParameters params = new XMSSParameters(10, new SHA256Digest(), new NullPRNG());
		byte[] root = { (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06,
				(byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c, (byte) 0x0d, (byte) 0x0e,
				(byte) 0x0f, (byte) 0x10, (byte) 0x20, (byte) 0x30, (byte) 0x03, (byte) 0x40, (byte) 0x50, (byte) 0x60,
				(byte) 0x70, (byte) 0x80, (byte) 0x90, (byte) 0xa0, (byte) 0xb0, (byte) 0xc0, (byte) 0xd0, (byte) 0xe0,
				(byte) 0xf0 };
		XMSSPrivateKeyParameters privateKey = null;
		try {
			privateKey = new XMSSPrivateKeyParameters.Builder(params).withIndex(0xaa).withRoot(root).build();
		} catch (ParseException ex) {
			/* should not happen */
			ex.printStackTrace();
		}
		byte[] export = privateKey.toByteArray();

		XMSSPrivateKeyParameters privateKey2 = null;
		try {
			privateKey2 = new XMSSPrivateKeyParameters.Builder(params).withPrivateKey(export, new XMSS(params)).build();
		} catch (ParseException ex) {
			ex.printStackTrace();
			fail();
		}
		assertEquals(privateKey.getIndex(), privateKey2.getIndex());
		assertEquals(true, XMSSUtil.compareByteArray(privateKey.getSecretKeySeed(), privateKey2.getSecretKeySeed()));
		assertEquals(true, XMSSUtil.compareByteArray(privateKey.getSecretKeyPRF(), privateKey2.getSecretKeyPRF()));
		assertEquals(true, XMSSUtil.compareByteArray(privateKey.getPublicSeed(), privateKey2.getPublicSeed()));
		assertEquals(true, XMSSUtil.compareByteArray(privateKey.getRoot(), privateKey2.getRoot()));
	}
}
