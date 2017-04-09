package org.bouncycastle.pqc.crypto.xmss;

import java.io.Serializable;

/**
 * Node of the binary tree.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSNode implements Serializable {

	private static final long serialVersionUID = 1L;
	
	private int height;
	private byte[] value;
	
	public XMSSNode(int height, byte[] value) {
		super();
		this.height = height;
		this.value = value;
	}

	public int getHeight() {
		return height;
	}
	
	public void setHeight(int height) {
		this.height = height;
	}

	public byte[] getValue() {
		return XMSSUtil.cloneArray(value);
	}
	
	public void setValue(byte[] value) {
		this.value = value;
	}
	
	@Override
    public XMSSNode clone() {
		return new XMSSNode(getHeight(), getValue());
    }
}
