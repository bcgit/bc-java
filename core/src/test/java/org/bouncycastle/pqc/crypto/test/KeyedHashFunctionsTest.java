package org.bouncycastle.pqc.crypto.test;

import java.util.Arrays;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.pqc.crypto.xmss.HashTreeAddress;
import org.bouncycastle.pqc.crypto.xmss.KeyedHashFunctions;
import org.bouncycastle.pqc.crypto.xmss.LTreeAddress;
import org.bouncycastle.pqc.crypto.xmss.OTSHashAddress;
import org.bouncycastle.pqc.crypto.xmss.XMSSAddress;
import org.bouncycastle.util.encoders.Hex;

import junit.framework.TestCase;

/**
 * Test cases for KeyedHashFunctions class.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class KeyedHashFunctionsTest extends TestCase {

	KeyedHashFunctions khfSHA256;
	KeyedHashFunctions khfSHA512;
	private byte[] key1;
	private byte[] key2;
	private byte[] key3;
	private byte[] key4;
	private byte[] key5;
	private byte[] key6;
	private XMSSAddress addr1;
	private XMSSAddress addr2;
	private XMSSAddress addr3;
	
	public void setUp() {
		Digest sha256 = new SHA256Digest();
		Digest sha512 = new SHA512Digest();
		khfSHA256 = new KeyedHashFunctions(sha256, sha256.getDigestSize());
		khfSHA512 = new KeyedHashFunctions(sha512, sha512.getDigestSize());
		key1 = new byte[32];
		key2 = new byte[32];
		key3 = new byte[32];
		key4 = new byte[64];
		key5 = new byte[64];
		key6 = new byte[64];
		Arrays.fill(key1, (byte) 0x00);
		Arrays.fill(key2, (byte) 0xff);
		Arrays.fill(key3, (byte) 0xab);
		Arrays.fill(key4, (byte) 0x00);
		Arrays.fill(key5, (byte) 0xff);
		Arrays.fill(key6, (byte) 0xab);
		addr1 = new OTSHashAddress();
		addr2 = new LTreeAddress();
		addr3 = new HashTreeAddress();
	}
	
	public void testPRF() {
		// SHA256
		byte[] hash = khfSHA256.PRF(key1, addr1.toByteArray());
		assertEquals("6945a6f13aa83e598cb8d0abebb5cddbd87e576226517f9001c1d36bb320bf80", Hex.toHexString(hash));
		hash = khfSHA256.PRF(key2, addr2.toByteArray());
		assertEquals("fd4016a59da88676579096a957312a4d12d9c35ba5a350640b5403cc71d8e181", Hex.toHexString(hash));
		hash = khfSHA256.PRF(key3, addr3.toByteArray());
		assertEquals("26a47454f97535b34b0b2aea9eec8f06a9feca6de21591302d1986823bd0b02d", Hex.toHexString(hash));
		// SHA512
		hash = khfSHA512.PRF(key4, addr1.toByteArray());
		assertEquals("25fc9eb157c443b49dcaf5b76d21086c79dd06fa474fd2b1046bc975855484b9618a442b4f2377a549eaa657c4a2a0dc9b7ea329a93382ef777a2ed402c88973", Hex.toHexString(hash));
		hash = khfSHA512.PRF(key5, addr2.toByteArray());
		assertEquals("6f2eb1015e70231d14e8e4ef944740c25752a4d6ef1b4f2b0bd3ce437bc8b933b3733386e688f780a829603814cc983ba97b8c852762d735925d6e5691c192a0", Hex.toHexString(hash));
		hash = khfSHA512.PRF(key6, addr3.toByteArray());
		assertEquals("296c99385cccf2a635a464e92dcc5e34046b1c2bc963caf780c624b710ce837be1b71936c140ce143d10bcb4b2a0d7c9e7e630e9edc1009fef2ec8a315ff404a", Hex.toHexString(hash));
	}
}
