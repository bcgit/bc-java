package org.bouncycastle.pqc.crypto.test;

import junit.framework.TestCase;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPublicKeyParameters;
import org.bouncycastle.util.Arrays;

/**
 * Test cases for XMSSPublicKey class.
 * 
 */
public class XMSSPublicKeyTest extends TestCase {

	public void testPublicKeyParsingSHA256() {
		XMSSParameters params = new XMSSParameters(10, new SHA256Digest());
		byte[] root = { (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06,
				(byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c, (byte) 0x0d, (byte) 0x0e,
				(byte) 0x0f, (byte) 0x10, (byte) 0x20, (byte) 0x30, (byte) 0x03, (byte) 0x40, (byte) 0x50, (byte) 0x60,
				(byte) 0x70, (byte) 0x80, (byte) 0x90, (byte) 0xa0, (byte) 0xb0, (byte) 0xc0, (byte) 0xd0, (byte) 0xe0,
				(byte) 0xf0 };
		XMSSPublicKeyParameters publicKey = new XMSSPublicKeyParameters.Builder(params).withRoot(root).build();

		byte[] export = publicKey.toByteArray();

		XMSSPublicKeyParameters publicKey2 = new XMSSPublicKeyParameters.Builder(params).withPublicKey(export).build();

		assertEquals(true, Arrays.areEqual(publicKey.getRoot(), publicKey2.getRoot()));
		assertEquals(true, Arrays.areEqual(publicKey.getPublicSeed(), publicKey2.getPublicSeed()));
	}

	public void testPublicKeyParsingSHA512() {
		XMSSParameters params = new XMSSParameters(10, new SHA512Digest());
		byte[] root = { (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06,
				(byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c, (byte) 0x0d, (byte) 0x0e,
				(byte) 0x0f, (byte) 0x10, (byte) 0x20, (byte) 0x30, (byte) 0x03, (byte) 0x40, (byte) 0x50, (byte) 0x60,
				(byte) 0x70, (byte) 0x80, (byte) 0x90, (byte) 0xa0, (byte) 0xb0, (byte) 0xc0, (byte) 0xd0, (byte) 0xe0,
				(byte) 0xf0, (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06,
				(byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c, (byte) 0x0d, (byte) 0x0e,
				(byte) 0x0f, (byte) 0x10, (byte) 0x20, (byte) 0x30, (byte) 0x03, (byte) 0x40, (byte) 0x50, (byte) 0x60,
				(byte) 0x70, (byte) 0x80, (byte) 0x90, (byte) 0xa0, (byte) 0xb0, (byte) 0xc0, (byte) 0xd0, (byte) 0xe0,
				(byte) 0xf0 };
		XMSSPublicKeyParameters publicKey = new XMSSPublicKeyParameters.Builder(params).withRoot(root).build();

		byte[] export = publicKey.toByteArray();

		XMSSPublicKeyParameters publicKey2 = new XMSSPublicKeyParameters.Builder(params).withPublicKey(export).build();

		assertEquals(true, Arrays.areEqual(publicKey.getRoot(), publicKey2.getRoot()));
		assertEquals(true, Arrays.areEqual(publicKey.getPublicSeed(), publicKey2.getPublicSeed()));
	}

	public void testConstructor() {
		XMSSParameters params = new XMSSParameters(10, new SHA256Digest());
		XMSSPublicKeyParameters pk = new XMSSPublicKeyParameters.Builder(params).build();

		byte[] pkByte = pk.toByteArray();
		/* check everything is 0 */
		for (int i = 5; i < pkByte.length; i++) {
			assertEquals(0x00, pkByte[i]);
		}
	}
}
