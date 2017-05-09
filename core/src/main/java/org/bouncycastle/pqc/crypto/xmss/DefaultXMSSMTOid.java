package org.bouncycastle.pqc.crypto.xmss;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * XMSSOid^MT class.
 *
 */
public final class DefaultXMSSMTOid implements XMSSOid {

	/**
	 * XMSS^MT OID lookup table.
	 */
	private static final Map<String, DefaultXMSSMTOid> oidLookupTable;

	static {
		Map<String, DefaultXMSSMTOid> map = new HashMap<String, DefaultXMSSMTOid>();
		map.put(createKey("SHA-256", 32, 16, 67, 20, 2),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-256_W16_H20_D2"));
		map.put(createKey("SHA-256", 32, 16, 67, 20, 4),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-256_W16_H20_D4"));
		map.put(createKey("SHA-256", 32, 16, 67, 40, 2),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-256_W16_H40_D2"));
		map.put(createKey("SHA-256", 32, 16, 67, 40, 2),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-256_W16_H40_D4"));
		map.put(createKey("SHA-256", 32, 16, 67, 40, 4),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-256_W16_H40_D8"));
		map.put(createKey("SHA-256", 32, 16, 67, 60, 8),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-256_W16_H60_D3"));
		map.put(createKey("SHA-256", 32, 16, 67, 60, 6),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-256_W16_H60_D6"));
		map.put(createKey("SHA-256", 32, 16, 67, 60, 12),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-256_W16_H60_D12"));
		map.put(createKey("SHA2-512", 64, 16, 131, 20, 2),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-512_W16_H20_D2"));
		map.put(createKey("SHA2-512", 64, 16, 131, 20, 4),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-512_W16_H20_D4"));
		map.put(createKey("SHA2-512", 64, 16, 131, 40, 2),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-512_W16_H40_D2"));
		map.put(createKey("SHA2-512", 64, 16, 131, 40, 4),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-512_W16_H40_D4"));
		map.put(createKey("SHA2-512", 64, 16, 131, 40, 8),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-512_W16_H40_D8"));
		map.put(createKey("SHA2-512", 64, 16, 131, 60, 3),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-512_W16_H60_D3"));
		map.put(createKey("SHA2-512", 64, 16, 131, 60, 6),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-512_W16_H60_D6"));
		map.put(createKey("SHA2-512", 64, 16, 131, 60, 12),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-512_W16_H60_D12"));
		map.put(createKey("SHAKE128", 32, 16, 67, 20, 2),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE128_W16_H20_D2"));
		map.put(createKey("SHAKE128", 32, 16, 67, 20, 4),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE128_W16_H20_D4"));
		map.put(createKey("SHAKE128", 32, 16, 67, 40, 2),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE128_W16_H40_D2"));
		map.put(createKey("SHAKE128", 32, 16, 67, 40, 4),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE128_W16_H40_D4"));
		map.put(createKey("SHAKE128", 32, 16, 67, 40, 8),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE128_W16_H40_D8"));
		map.put(createKey("SHAKE128", 32, 16, 67, 60, 3),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE128_W16_H60_D3"));
		map.put(createKey("SHAKE128", 32, 16, 67, 60, 6),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE128_W16_H60_D6"));
		map.put(createKey("SHAKE128", 32, 16, 67, 60, 12),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE128_W16_H60_D12"));
		map.put(createKey("SHAKE256", 64, 16, 131, 20, 2),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE256_W16_H20_D2"));
		map.put(createKey("SHAKE256", 64, 16, 131, 20, 4),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE256_W16_H20_D4"));
		map.put(createKey("SHAKE256", 64, 16, 131, 40, 2),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE256_W16_H40_D2"));
		map.put(createKey("SHAKE256", 64, 16, 131, 40, 4),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE256_W16_H40_D4"));
		map.put(createKey("SHAKE256", 64, 16, 131, 40, 8),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE256_W16_H40_D8"));
		map.put(createKey("SHAKE256", 64, 16, 131, 60, 3),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE256_W16_H60_D3"));
		map.put(createKey("SHAKE256", 64, 16, 131, 60, 6),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE256_W16_H60_D6"));
		map.put(createKey("SHAKE256", 64, 16, 131, 60, 12),
				new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE256_W16_H60_D12"));
		oidLookupTable = Collections.unmodifiableMap(map);
	}

	/**
	 * OID.
	 */
	private final int oid;
	/**
	 * String representation of OID.
	 */
	private final String stringRepresentation;

	/**
	 * Constructor...
	 *
	 * @param oid
	 *            OID.
	 * @param stringRepresentation
	 *            String representation of OID.
	 */
	private DefaultXMSSMTOid(int oid, String stringRepresentation) {
		super();
		this.oid = oid;
		this.stringRepresentation = stringRepresentation;
	}

	/**
	 * Lookup OID.
	 *
	 * @param algorithmName
	 *            Algorithm name.
	 * @param winternitzParameter
	 *            Winternitz parameter.
	 * @param height
	 *            Binary tree height.
	 * @return XMSS OID if parameters were found, null else.
	 */
	public static DefaultXMSSMTOid lookup(String algorithmName, int digestSize, int winternitzParameter, int len,
			int height, int layers) {
		if (algorithmName == null) {
			throw new NullPointerException("algorithmName == null");
		}
		return oidLookupTable.get(createKey(algorithmName, digestSize, winternitzParameter, len, height, layers));
	}

	/**
	 * Create a key based on parameters.
	 *
	 * @param algorithmName
	 *            Algorithm name.
	 * @param winternitzParameter
	 *            Winternitz Parameter.
	 * @param height
	 *            Binary tree height.
	 * @return String representation of parameters for lookup table.
	 */
	private static String createKey(String algorithmName, int digestSize, int winternitzParameter, int len, int height,
			int layers) {
		if (algorithmName == null) {
			throw new NullPointerException("algorithmName == null");
		}
		return algorithmName + "-" + digestSize + "-" + winternitzParameter + "-" + len + "-" + height + "-" + layers;
	}

	/**
	 * Getter OID.
	 *
	 * @return OID.
	 */
	public int getOid() {
		return oid;
	}

	public String toString() {
		return stringRepresentation;
	}
}
