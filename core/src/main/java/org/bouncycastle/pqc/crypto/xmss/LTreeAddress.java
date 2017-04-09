package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;

/**
 * 
 * XMSS L-tree address.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class LTreeAddress extends XMSSAddress {
	
	private static final int TYPE = 0x01;
	private int lTreeAddress;
	private int treeHeight;
	private int treeIndex;
	
	public LTreeAddress() {
		super(TYPE);
	}

	@Override
	public void parseByteArray(byte[] address) throws ParseException {
		int type = XMSSUtil.bytesToIntBigEndian(address, 12);
		if (type != TYPE) {
			throw new ParseException("type needs to be " + TYPE, 12);
		}
		setType(type);
		lTreeAddress = XMSSUtil.bytesToIntBigEndian(address, 16);
		treeHeight = XMSSUtil.bytesToIntBigEndian(address, 20);
		treeIndex = XMSSUtil.bytesToIntBigEndian(address, 24);
		super.parseByteArray(address);
	}

	@Override
	public byte[] toByteArray() {
		byte[] byteRepresentation = getByteRepresentation();
		XMSSUtil.intToBytesBigEndianOffset(byteRepresentation, lTreeAddress, 16);
		XMSSUtil.intToBytesBigEndianOffset(byteRepresentation, treeHeight, 20);
		XMSSUtil.intToBytesBigEndianOffset(byteRepresentation, treeIndex, 24);
		return super.toByteArray();
	}
	
	public int getLTreeAddress() {
		return lTreeAddress;
	}

	public void setLTreeAddress(int lTreeAddress) {
		this.lTreeAddress = lTreeAddress;
	}

	public int getTreeHeight() {
		return treeHeight;
	}

	public void setTreeHeight(int treeHeight) {
		this.treeHeight = treeHeight;
	}

	public int getTreeIndex() {
		return treeIndex;
	}

	public void setTreeIndex(int treeIndex) {
		this.treeIndex = treeIndex;
	}
}
