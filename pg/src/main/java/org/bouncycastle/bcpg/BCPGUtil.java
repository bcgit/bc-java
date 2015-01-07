package org.bouncycastle.bcpg;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class BCPGUtil {
	public static byte[] getEncoded(Encodeable obj) throws IOException {
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		BCPGOutputStream pgpOut = new BCPGOutputStream(bOut);

		if (obj instanceof BCPGObject) {
			pgpOut.writeObject((BCPGObject) obj);
		}

		if (obj instanceof ContainedPacket) {
			pgpOut.writePacket((ContainedPacket) obj);
		}
		pgpOut.close();

		return bOut.toByteArray();
	}

}
