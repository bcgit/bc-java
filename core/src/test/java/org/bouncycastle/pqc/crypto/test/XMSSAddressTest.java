package org.bouncycastle.pqc.crypto.test;

import java.text.ParseException;
import java.util.Arrays;

import org.bouncycastle.pqc.crypto.xmss.HashTreeAddress;
import org.bouncycastle.pqc.crypto.xmss.LTreeAddress;
import org.bouncycastle.pqc.crypto.xmss.OTSHashAddress;

import junit.framework.TestCase;

/**
 * Test cases for XMSSAddress classes.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSAddressTest extends TestCase {

	public void testOTSHashAddressToByteArray() {
		OTSHashAddress address = new OTSHashAddress();
		assertEquals(0x00, address.getType());
		address.setLayerAddress(0x00);
		address.setTreeAddress(0x11);
		address.setOTSAddress(0x22);
		address.setChainAddress(0x33);
		address.setHashAddress(0x44);
		address.setKeyAndMask(0x55);
		byte[] out = address.toByteArray();
		assertEquals(0x00, out[0]);
		assertEquals(0x00, out[1]);
		assertEquals(0x00, out[2]);
		assertEquals(0x00, out[3]);
		assertEquals(0x00, out[4]);
		assertEquals(0x00, out[5]);
		assertEquals(0x00, out[6]);
		assertEquals(0x00, out[7]);
		assertEquals(0x00, out[8]);
		assertEquals(0x00, out[9]);
		assertEquals(0x00, out[10]);
		assertEquals(0x11, out[11]);
		assertEquals(0x00, out[12]);
		assertEquals(0x00, out[13]);
		assertEquals(0x00, out[14]);
		assertEquals(0x00, out[15]);
		assertEquals(0x00, out[16]);
		assertEquals(0x00, out[17]);
		assertEquals(0x00, out[18]);
		assertEquals(0x22, out[19]);
		assertEquals(0x00, out[20]);
		assertEquals(0x00, out[21]);
		assertEquals(0x00, out[22]);
		assertEquals(0x33, out[23]);
		assertEquals(0x00, out[24]);
		assertEquals(0x00, out[25]);
		assertEquals(0x00, out[26]);
		assertEquals(0x44, out[27]);
		assertEquals(0x00, out[28]);
		assertEquals(0x00, out[29]);
		assertEquals(0x00, out[30]);
		assertEquals(0x55, out[31]);
	}
	
	public void testLTreeAddressToByteArray() {
		LTreeAddress address = new LTreeAddress();
		assertEquals(0x01, address.getType());
		address.setLayerAddress(0x00);
		address.setTreeAddress(0x11);
		address.setLTreeAddress(0x22);
		address.setTreeHeight(0x33);
		address.setTreeIndex(0x44);
		address.setKeyAndMask(0x55);
		byte[] out = address.toByteArray();
		assertEquals(0x00, out[0]);
		assertEquals(0x00, out[1]);
		assertEquals(0x00, out[2]);
		assertEquals(0x00, out[3]);
		assertEquals(0x00, out[4]);
		assertEquals(0x00, out[5]);
		assertEquals(0x00, out[6]);
		assertEquals(0x00, out[7]);
		assertEquals(0x00, out[8]);
		assertEquals(0x00, out[9]);
		assertEquals(0x00, out[10]);
		assertEquals(0x11, out[11]);
		assertEquals(0x00, out[12]);
		assertEquals(0x00, out[13]);
		assertEquals(0x00, out[14]);
		assertEquals(0x01, out[15]);
		assertEquals(0x00, out[16]);
		assertEquals(0x00, out[17]);
		assertEquals(0x00, out[18]);
		assertEquals(0x22, out[19]);
		assertEquals(0x00, out[20]);
		assertEquals(0x00, out[21]);
		assertEquals(0x00, out[22]);
		assertEquals(0x33, out[23]);
		assertEquals(0x00, out[24]);
		assertEquals(0x00, out[25]);
		assertEquals(0x00, out[26]);
		assertEquals(0x44, out[27]);
		assertEquals(0x00, out[28]);
		assertEquals(0x00, out[29]);
		assertEquals(0x00, out[30]);
		assertEquals(0x55, out[31]);
	}
	
	public void testHashTreeAddressToByteArray() {
		HashTreeAddress address = new HashTreeAddress();
		assertEquals(0x02, address.getType());
		address.setLayerAddress(0x00);
		address.setTreeAddress(0x11);
		address.setTreeHeight(0x33);
		address.setTreeIndex(0x44);
		address.setKeyAndMask(0x55);
		byte[] out = address.toByteArray();
		assertEquals(0x00, out[0]);
		assertEquals(0x00, out[1]);
		assertEquals(0x00, out[2]);
		assertEquals(0x00, out[3]);
		assertEquals(0x00, out[4]);
		assertEquals(0x00, out[5]);
		assertEquals(0x00, out[6]);
		assertEquals(0x00, out[7]);
		assertEquals(0x00, out[8]);
		assertEquals(0x00, out[9]);
		assertEquals(0x00, out[10]);
		assertEquals(0x11, out[11]);
		assertEquals(0x00, out[12]);
		assertEquals(0x00, out[13]);
		assertEquals(0x00, out[14]);
		assertEquals(0x02, out[15]);
		assertEquals(0x00, out[16]);
		assertEquals(0x00, out[17]);
		assertEquals(0x00, out[18]);
		assertEquals(0x00, out[19]);
		assertEquals(0x00, out[20]);
		assertEquals(0x00, out[21]);
		assertEquals(0x00, out[22]);
		assertEquals(0x33, out[23]);
		assertEquals(0x00, out[24]);
		assertEquals(0x00, out[25]);
		assertEquals(0x00, out[26]);
		assertEquals(0x44, out[27]);
		assertEquals(0x00, out[28]);
		assertEquals(0x00, out[29]);
		assertEquals(0x00, out[30]);
		assertEquals(0x55, out[31]);
	}

	public void testXAdressParseByteParamException() {
		OTSHashAddress hash = new OTSHashAddress();
		byte[] in = new byte[31];
		try {
			hash.parseByteArray(in);
			fail();
		} catch (Exception ex) { }
	}
	
	public void testOTSHashAddressParseByteArrayTypeException() {
		OTSHashAddress hash = new OTSHashAddress();
		byte[] in = new byte[32];
		in[15] = 0x11;
		try {
			hash.parseByteArray(in);
			fail();
		} catch (Exception ex) { }
	}
	
	public void testOTSHashAddressParseByteArray() {
		byte[] in = {
				0x11, 0x11, 0x11, 0x11,
				0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
				0x00, 0x00, 0x00, 0x00,
				0x33, 0x33, 0x33, 0x33,
				0x44, 0x44, 0x44, 0x44,
				0x55, 0x55, 0x55, 0x55,
				0x66, 0x66, 0x66, 0x66
		};
		OTSHashAddress hash = new OTSHashAddress();
		try {
			hash.parseByteArray(in);
		} catch (ParseException ex) {
			fail();
		}
		assertEquals(0x11111111, hash.getLayerAddress());
		assertEquals(0x2222222222222222L, hash.getTreeAddress());
		assertEquals(0x00, hash.getType());
		assertEquals(0x33333333, hash.getOTSAddress());
		assertEquals(0x44444444, hash.getChainAddress());
		assertEquals(0x55555555, hash.getHashAddress());
		assertEquals(0x66666666, hash.getKeyAndMask());
		byte[] out = hash.toByteArray();
		assertEquals(true, Arrays.equals(in, out));
	}
	
	public void testLTreeAddressParseByteArrayTypeException() {
		LTreeAddress lTree = new LTreeAddress();
		byte[] in = new byte[32];
		in[15] = 0x11;
		try {
			lTree.parseByteArray(in);
			fail();
		} catch (Exception ex) { }
	}
	
	public void testLTreeAddressParseByteArray() {
		byte[] in = {
				0x11, 0x11, 0x11, 0x11,
				0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
				0x00, 0x00, 0x00, 0x01,
				0x33, 0x33, 0x33, 0x33,
				0x44, 0x44, 0x44, 0x44,
				0x55, 0x55, 0x55, 0x55,
				0x66, 0x66, 0x66, 0x66
		};
		LTreeAddress hash = new LTreeAddress();
		try {
			hash.parseByteArray(in);
		} catch (ParseException ex) {
			fail();
		}
		assertEquals(0x11111111, hash.getLayerAddress());
		assertEquals(0x2222222222222222L, hash.getTreeAddress());
		assertEquals(0x01, hash.getType());
		assertEquals(0x33333333, hash.getLTreeAddress());
		assertEquals(0x44444444, hash.getTreeHeight());
		assertEquals(0x55555555, hash.getTreeIndex());
		assertEquals(0x66666666, hash.getKeyAndMask());
		byte[] out = hash.toByteArray();
		assertEquals(true, Arrays.equals(in, out));
	}
	
	public void testHashTreeAddressParseByteArrayTypeException() {
		HashTreeAddress hash = new HashTreeAddress();
		byte[] in = new byte[32];
		in[15] = 0x11;
		try {
			hash.parseByteArray(in);
			fail();
		} catch (Exception ex) { }
	}
	
	public void testHashTreeAddressParseByteArrayPaddingException() {
		HashTreeAddress hash = new HashTreeAddress();
		byte[] in = new byte[32];
		in[16] = 0x11;
		try {
			hash.parseByteArray(in);
			fail();
		} catch (Exception ex) { }
	}
	
	public void testHashTreeAddressParseByteArray() {
		byte[] in = {
				0x11, 0x11, 0x11, 0x11,
				0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
				0x00, 0x00, 0x00, 0x02,
				0x00, 0x00, 0x00, 0x00,
				0x44, 0x44, 0x44, 0x44,
				0x55, 0x55, 0x55, 0x55,
				0x66, 0x66, 0x66, 0x66
		};
		HashTreeAddress hash = new HashTreeAddress();
		try {
			hash.parseByteArray(in);
		} catch (ParseException ex) {
			fail();
		}
		assertEquals(0x11111111, hash.getLayerAddress());
		assertEquals(0x2222222222222222L, hash.getTreeAddress());
		assertEquals(0x02, hash.getType());
		assertEquals(0x00, hash.getPadding());
		assertEquals(0x44444444, hash.getTreeHeight());
		assertEquals(0x55555555, hash.getTreeIndex());
		assertEquals(0x66666666, hash.getKeyAndMask());
		byte[] out = hash.toByteArray();
		assertEquals(true, Arrays.equals(in, out));
	}
}
