package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;

/**
 * Interface for XMSS objects that need to be storeable as a byte array.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public interface XMSSStoreableObjectInterface {

	/**
	 * Create byte representation of object.
	 * @return Byte representation of object.
	 */
	public byte[] toByteArray();

	/**
	 * Fill object from byte representation.
	 * @param in Byte representation of object.
	 * @throws ParseException
	 */
	public void parseByteArray(byte[] in) throws ParseException;
}
