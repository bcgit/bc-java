package org.bouncycastle.pqc.crypto.xmss;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.encoders.Hex;

/**
 * Utils for XMSS implementation.
 *
 */
public class XMSSUtil {

	/**
	 * Calculates the logarithm base 2 for a given Integer.
	 *
	 * @param n
	 *            Number.
	 * @return Logarithm to base 2 of {@code n}.
	 */
	public static int log2(int n) {
		int log = 0;
		while ((n >>= 1) != 0) {
			log++;
		}
		return log;
	}

	/**
	 * Convert int/long to n-byte array.
	 *
	 * @param value
	 *            int/long value.
	 * @param sizeInByte
	 *            Size of byte array in byte.
	 * @return int/long as big-endian byte array of size {@code sizeInByte}.
	 */
	public static byte[] toBytesBigEndian(long value, int sizeInByte) {
		byte[] out = new byte[sizeInByte];
		for (int i = (sizeInByte - 1); i >= 0; i--) {
			out[i] = (byte) value;
			value >>>= 8;
		}
		return out;
	}

	/**
	 * Copy int to byte array in big-endian at specific offset.
	 *
	 * @param Byte
	 *            array.
	 * @param Integer
	 *            to put.
	 * @param Offset
	 *            in {@code in}.
	 */
	public static void intToBytesBigEndianOffset(byte[] in, int value, int offset) {
		if (in == null) {
			throw new NullPointerException("in == null");
		}
		if ((in.length - offset) < 4) {
			throw new IllegalArgumentException("not enough space in array");
		}
		in[offset] = (byte) ((value >> 24) & 0xff);
		in[offset + 1] = (byte) ((value >> 16) & 0xff);
		in[offset + 2] = (byte) ((value >> 8) & 0xff);
		in[offset + 3] = (byte) ((value) & 0xff);
	}

	/**
	 * Copy long to byte array in big-endian at specific offset.
	 *
	 * @param Byte
	 *            array.
	 * @param Long
	 *            to put.
	 * @param Offset
	 *            in {@code in}.
	 */
	public static void longToBytesBigEndianOffset(byte[] in, long value, int offset) {
		if (in == null) {
			throw new NullPointerException("in == null");
		}
		if ((in.length - offset) < 8) {
			throw new IllegalArgumentException("not enough space in array");
		}
		in[offset] = (byte) ((value >> 56) & 0xff);
		in[offset + 1] = (byte) ((value >> 48) & 0xff);
		in[offset + 2] = (byte) ((value >> 40) & 0xff);
		in[offset + 3] = (byte) ((value >> 32) & 0xff);
		in[offset + 4] = (byte) ((value >> 24) & 0xff);
		in[offset + 5] = (byte) ((value >> 16) & 0xff);
		in[offset + 6] = (byte) ((value >> 8) & 0xff);
		in[offset + 7] = (byte) ((value) & 0xff);
	}

	/**
	 * Generic convert from big endian byte array to long.
	 *
	 * @param x-byte
	 *            array
	 * @param offset.
	 * @param size.
	 * @return Long.
	 */
	public static long bytesToXBigEndian(byte[] in, int offset, int size) {
		if (in == null) {
			throw new NullPointerException("in == null");
		}
		long res = 0;
		for (int i = offset; i < (offset + size); i++) {
			res = (res << 8) | (in[i] & 0xff);
		}
		return res;
	}

	/**
	 * Clone a byte array.
	 *
	 * @param in
	 *            byte array.
	 * @return Copy of byte array.
	 */
	public static byte[] cloneArray(byte[] in) {
		if (in == null) {
			throw new NullPointerException("in == null");
		}
		byte[] out = new byte[in.length];
		for (int i = 0; i < in.length; i++) {
			out[i] = in[i];
		}
		return out;
	}

	/**
	 * Clone a 2d byte array.
	 *
	 * @param in
	 *            2d byte array.
	 * @return Copy of 2d byte array.
	 */
	public static byte[][] cloneArray(byte[][] in) {
		if (hasNullPointer(in)) {
			throw new NullPointerException("in has null pointers");
		}
		byte[][] out = new byte[in.length][];
		for (int i = 0; i < in.length; i++) {
			out[i] = new byte[in[i].length];
			for (int j = 0; j < in[i].length; j++) {
				out[i][j] = in[i][j];
			}
		}
		return out;
	}

	/**
	 * Concatenates an arbitrary number of byte arrays.
	 *
	 * @param arrays
	 *            Arrays that shall be concatenated.
	 * @return Concatenated array.
	 */
	public static byte[] concat(byte[]... arrays) {
		int totalLength = 0;
		for (int i = 0; i < arrays.length; i++) {
			totalLength += arrays[i].length;
		}
		byte[] result = new byte[totalLength];
		int currentIndex = 0;
		for (int i = 0; i < arrays.length; i++) {
			System.arraycopy(arrays[i], 0, result, currentIndex, arrays[i].length);
			currentIndex += arrays[i].length;
		}
		return result;
	}

	/**
	 * Compares two byte arrays.
	 *
	 * @param a
	 *            byte array 1.
	 * @param b
	 *            byte array 2.
	 * @return true if all values in byte array are equal false else.
	 */
	public static boolean compareByteArray(byte[] a, byte[] b) {
		if (a == null || b == null) {
			throw new NullPointerException("a or b == null");
		}
		if (a.length != b.length) {
			throw new IllegalArgumentException("size of a and b must be equal");
		}
		for (int i = 0; i < a.length; i++) {
			if (a[i] != b[i]) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Compares two 2d-byte arrays.
	 *
	 * @param a
	 *            2d-byte array 1.
	 * @param b
	 *            2d-byte array 2.
	 * @return true if all values in 2d-byte array are equal false else.
	 */
	public static boolean compareByteArray(byte[][] a, byte[][] b) {
		if (hasNullPointer(a) || hasNullPointer(b)) {
			throw new NullPointerException("a or b == null");
		}
		for (int i = 0; i < a.length; i++) {
			if (!compareByteArray(a[i], b[i])) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Dump content of 2d byte array.
	 *
	 * @param x
	 *            byte array.
	 */
	public static void dumpByteArray(byte[][] x) {
		if (hasNullPointer(x)) {
			throw new NullPointerException("x has null pointers");
		}
		for (int i = 0; i < x.length; i++) {
			System.out.println(Hex.toHexString(x[i]));
		}
	}

	/**
	 * Checks whether 2d byte array has null pointers.
	 *
	 * @param in
	 *            2d byte array.
	 * @return true if at least one null pointer is found false else.
	 */
	public static boolean hasNullPointer(byte[][] in) {
		if (in == null) {
			return true;
		}
		for (int i = 0; i < in.length; i++) {
			if (in[i] == null) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Copy src byte array to dst byte array at offset.
	 *
	 * @param dst
	 *            Destination.
	 * @param src
	 *            Source.
	 * @param offset
	 *            Destination offset.
	 */
	public static void copyBytesAtOffset(byte[] dst, byte[] src, int offset) {
		if (dst == null) {
			throw new NullPointerException("dst == null");
		}
		if (src == null) {
			throw new NullPointerException("src == null");
		}
		if (offset < 0) {
			throw new IllegalArgumentException("offset hast to be >= 0");
		}
		if ((src.length + offset) > dst.length) {
			throw new IllegalArgumentException("src length + offset must not be greater than size of destination");
		}
		for (int i = 0; i < src.length; i++) {
			dst[offset + i] = src[i];
		}
	}

	/**
	 * Copy length bytes at position offset from src.
	 *
	 * @param src
	 *            Source byte array.
	 * @param offset
	 *            Offset in source byte array.
	 * @param length
	 *            Length of bytes to copy.
	 * @return New byte array.
	 */
	public static byte[] extractBytesAtOffset(byte[] src, int offset, int length) {
		if (src == null) {
			throw new NullPointerException("src == null");
		}
		if (offset < 0) {
			throw new IllegalArgumentException("offset hast to be >= 0");
		}
		if (length < 0) {
			throw new IllegalArgumentException("length hast to be >= 0");
		}
		if ((offset + length) > src.length) {
			throw new IllegalArgumentException("offset + length must not be greater then size of source array");
		}
		byte[] out = new byte[length];
		for (int i = 0; i < out.length; i++) {
			out[i] = src[offset + i];
		}
		return out;
	}

	/**
	 * Check whether an index is valid or not.
	 *
	 * @param height
	 *            Height of binary tree.
	 * @param index
	 *            Index to validate.
	 * @return true if index is valid false else.
	 */
	public static boolean isIndexValid(int height, long index) {
		if (index < 0) {
			throw new IllegalStateException("index must not be negative");
		}
		return index < (1L << height);
	}

	/**
	 * Determine digest size of digest.
	 *
	 * @param digest
	 *            Digest.
	 * @return Digest size.
	 */
	public static int getDigestSize(Digest digest) {
		if (digest == null) {
			throw new NullPointerException("digest == null");
		}
		String algorithmName = digest.getAlgorithmName();
		if (algorithmName.equals("SHAKE128")) {
			return 32;
		}
		if (algorithmName.equals("SHAKE256")) {
			return 64;
		}
		return digest.getDigestSize();
	}

	public static long getTreeIndex(long index, int xmssTreeHeight) {
		return index >> xmssTreeHeight;
	}

	public static int getLeafIndex(long index, int xmssTreeHeight) {
		return (int) (index & ((1L << xmssTreeHeight) - 1L));
	}

	public static byte[] serialize(Object obj) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(out);
		oos.writeObject(obj);
		oos.flush();
		return out.toByteArray();
	}

	public static Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
		ByteArrayInputStream in = new ByteArrayInputStream(data);
		ObjectInputStream is = new ObjectInputStream(in);
		return is.readObject();
	}

	public static int calculateTau(int index, int height) {
		int tau = 0;
		for (int i = 0; i < height; i++) {
			if (((index >> i) & 1) == 0) {
				tau = i;
				break;
			}
		}
		return tau;
	}

	public static boolean isNewBDSInitNeeded(long globalIndex, int xmssHeight, int layer) {
		if (globalIndex == 0) {
			return false;
		}
		return (globalIndex % (long) Math.pow((1 << xmssHeight), layer + 1) == 0) ? true : false;
	}

	public static boolean isNewAuthenticationPathNeeded(long globalIndex, int xmssHeight, int layer) {
		if (globalIndex == 0) {
			return false;
		}
		return ((globalIndex + 1) % (long) Math.pow((1 << xmssHeight), layer) == 0) ? true : false;
	}
}
