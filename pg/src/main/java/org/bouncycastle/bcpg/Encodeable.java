package org.bouncycastle.bcpg;

import java.io.IOException;

public interface Encodeable {
	public void encode(BCPGOutputStream out) throws IOException;
}
