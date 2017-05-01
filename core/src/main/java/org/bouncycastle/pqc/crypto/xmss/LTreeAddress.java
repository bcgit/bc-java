package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;

/**
 * L-tree address.
 *
 */
public final class LTreeAddress extends XMSSAddress {

	private static final int TYPE = 0x01;
	
	private final int lTreeAddress;
	private final int treeHeight;
	private final int treeIndex;

	private LTreeAddress(Builder builder) {
		super(builder);
		lTreeAddress = builder.lTreeAddress;
		treeHeight = builder.treeHeight;
		treeIndex = builder.treeIndex;
	}
	
	protected static class Builder extends XMSSAddress.Builder<Builder> {

		/* optional */
		private int lTreeAddress = 0;
		private int treeHeight = 0;
		private int treeIndex = 0;

		protected Builder() {
			super(TYPE);
		}
		
		protected Builder withLTreeAddress(int val) {
			lTreeAddress = val;
			return this;
		}
		
		protected Builder withTreeHeight(int val) {
			treeHeight = val;
			return this;
		}
		
		protected Builder withTreeIndex(int val) {
			treeIndex = val;
			return this;
		}
		
		@Override
		protected XMSSAddress build() {
			return new LTreeAddress(this);
		}

		@Override
		protected Builder getThis() {
			return this;
		}
	}

	@Override
	protected byte[] toByteArray() {
		byte[] byteRepresentation = super.toByteArray();
		XMSSUtil.intToBytesBigEndianOffset(byteRepresentation, lTreeAddress, 16);
		XMSSUtil.intToBytesBigEndianOffset(byteRepresentation, treeHeight, 20);
		XMSSUtil.intToBytesBigEndianOffset(byteRepresentation, treeIndex, 24);
		return byteRepresentation;
	}

	protected int getLTreeAddress() {
		return lTreeAddress;
	}
	
	protected int getTreeHeight() {
		return treeHeight;
	}
	
	protected int getTreeIndex() {
		return treeIndex;
	}
}
