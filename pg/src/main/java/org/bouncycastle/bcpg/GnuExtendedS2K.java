package org.bouncycastle.bcpg;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.S2K;

/**
 * Add a constructor fort GNU-extended S2K
 *
 * This extension is documented on GnuPG documentation DETAILS file,
 * section "GNU extensions to the S2K algorithm". Its support is
 * already present in S2K class but lack for a constructor.
 *
 * @author Léonard Dallot <leonard.dallot@taztag.com>
 */
public class GnuExtendedS2K extends S2K {

	public GnuExtendedS2K(int mode) {
		super(0x0);
		this.type = GNU_DUMMY_S2K;
		this.protectionMode = mode;
	}
}
