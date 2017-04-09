package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Xof;

/**
 * Crypto functions for XMSS.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class KeyedHashFunctions {

	private Digest digest;
	private int digestSize;
	
	public KeyedHashFunctions(Digest digest, int digestSize) {
		super();
		if (digest == null) {
			throw new NullPointerException("digest == null");
		}
		this.digest = digest;
		this.digestSize = digestSize;
	}
	
	private byte[] coreDigest(int fixedValue, byte[] key, byte[] index) {
		byte[] buffer = new byte[digestSize + key.length + index.length];
		byte[] in = XMSSUtil.toBytesBigEndian(fixedValue, digestSize);
		/* fill first n byte of out buffer */
		for (int i = 0; i < in.length; i++) {
			buffer[i] = in[i];
		}
		/* add key */
		for (int i = 0; i < key.length; i++) {
			buffer[in.length + i] = key[i];
		}
		/* add index */
		for (int i = 0; i < index.length; i++) {
			buffer[in.length + key.length + i] = index[i];
		}
		digest.update(buffer, 0, buffer.length);
		byte[] out = new byte[digestSize];
		if (digest instanceof Xof) {
			((Xof) digest).doFinal(out, 0, digestSize);
		} else {
			digest.doFinal(out, 0);
		}
		return out;
	}
	
	public byte[] F(byte[] key, byte[] in) {
		if (key.length != digestSize) {
			throw new IllegalArgumentException("wrong key length");
		}
		if (in.length != digestSize) {
			throw new IllegalArgumentException("wrong in length");
		}
		return coreDigest(0, key, in);
	}
	
	public byte[] H(byte[] key, byte[] in) {
		if (key.length != digestSize) {
			throw new IllegalArgumentException("wrong key length");
		}
		if (in.length != (2 * digestSize)) {
			throw new IllegalArgumentException("wrong in length");
		}
		return coreDigest(1, key, in);
	}
	
	public byte[] H(byte[] in, byte[] pubSeed, XMSSAddress addr) {
		if (pubSeed.length != digestSize) {
			throw new IllegalArgumentException("wrong key length");
		}
		addr.setKeyAndMask(0);
		byte[] key = PRF(pubSeed, addr.toByteArray());
		addr.setKeyAndMask(1);
		byte[] bitmask = PRF(pubSeed, addr.toByteArray());
		addr.setKeyAndMask(2);
		byte[] bitmask2 = PRF(pubSeed, addr.toByteArray());
		byte[] tmpMask = new byte[2 * digestSize];
		for (int i = 0; i < digestSize; i++) {
			tmpMask[i] = (byte)(in[i] ^ bitmask[i]);
		}
		for (int i = 0; i < digestSize; i++) {
			tmpMask[i+digestSize] = (byte)(in[i + digestSize] ^ bitmask2[i]);
		}
		byte[] result = coreDigest(1, key, tmpMask);
		return result;
	}
	
	public byte[] HMsg(byte[] key, byte[] in) {
		if (key.length != (3 * digestSize)) {
			throw new IllegalArgumentException("wrong key length");
		}
		return coreDigest(2, key, in);
	}
	
	public byte[] PRF(byte[] key, byte[] address) {
		if (key.length != digestSize) {
			throw new IllegalArgumentException("wrong key length");
		}
		if (address.length != 32) {
			throw new IllegalArgumentException("wrong address length");
		}
		return coreDigest(3, key, address);
	}
}
