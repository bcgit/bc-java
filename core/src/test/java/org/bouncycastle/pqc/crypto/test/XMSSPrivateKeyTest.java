package org.bouncycastle.pqc.crypto.test;

import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import org.bouncycastle.util.Arrays;

/**
 * Test cases for XMSSPrivateKey class.
 * 
 */
public class XMSSPrivateKeyTest extends TestCase {

	public void testPrivateKeyParsing() throws ClassNotFoundException, IOException {
		XMSSParameters params = new XMSSParameters(10, new SHA256Digest());
		byte[] root = { (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06,
				(byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c, (byte) 0x0d, (byte) 0x0e,
				(byte) 0x0f, (byte) 0x10, (byte) 0x20, (byte) 0x30, (byte) 0x03, (byte) 0x40, (byte) 0x50, (byte) 0x60,
				(byte) 0x70, (byte) 0x80, (byte) 0x90, (byte) 0xa0, (byte) 0xb0, (byte) 0xc0, (byte) 0xd0, (byte) 0xe0,
				(byte) 0xf0 };
		XMSSPrivateKeyParameters privateKey = new XMSSPrivateKeyParameters.Builder(params).withRoot(root).build();

		byte[] export = privateKey.toByteArray();

		XMSSPrivateKeyParameters privateKey2 = new XMSSPrivateKeyParameters.Builder(params).withPrivateKey(export, params).build();

		assertEquals(privateKey.getIndex(), privateKey2.getIndex());
		assertEquals(true, Arrays.areEqual(privateKey.getSecretKeySeed(), privateKey2.getSecretKeySeed()));
		assertEquals(true, Arrays.areEqual(privateKey.getSecretKeyPRF(), privateKey2.getSecretKeyPRF()));
		assertEquals(true, Arrays.areEqual(privateKey.getPublicSeed(), privateKey2.getPublicSeed()));
		assertEquals(true, Arrays.areEqual(privateKey.getRoot(), privateKey2.getRoot()));
	}
}
