package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;

/**
 * XMSS address.
 *
 */
public abstract class XMSSAddress {

	private final int layerAddress;
	private final long treeAddress;
	private final int type;
	private final int keyAndMask;

	protected XMSSAddress(Builder builder) {
		layerAddress = builder.layerAddress;
		treeAddress = builder.treeAddress;
		type = builder.type;
		keyAndMask = builder.keyAndMask;
	}

	protected static abstract class Builder<T extends Builder> {

		/* mandatory */
		private final int type;
		/* optional */
		private int layerAddress = 0;
		private long treeAddress = 0L;
		private int keyAndMask = 0;

		protected Builder(int type) {
			super();
			this.type = type;
		}

		protected T withLayerAddress(int val) {
			layerAddress = val;
			return getThis();
		}
		
		protected T withTreeAddress(long val) {
			treeAddress = val;
			return getThis();
		}
		
		protected T withKeyAndMask(int val) {
			keyAndMask = val;
			return getThis();
		}
		
		protected abstract XMSSAddress build();
		protected abstract T getThis();
	}

	protected byte[] toByteArray() {
		byte[] byteRepresentation = new byte[32];
		XMSSUtil.intToBytesBigEndianOffset(byteRepresentation, layerAddress, 0);
		XMSSUtil.longToBytesBigEndianOffset(byteRepresentation, treeAddress, 4);
		XMSSUtil.intToBytesBigEndianOffset(byteRepresentation, type, 12);
		XMSSUtil.intToBytesBigEndianOffset(byteRepresentation, keyAndMask, 28);
		return byteRepresentation;
	}

	protected final int getLayerAddress() {
		return layerAddress;
	}

	protected final long getTreeAddress() {
		return treeAddress;
	}

	public final int getType() {
		return type;
	}

	public final int getKeyAndMask() {
		return keyAndMask;
	}
}
