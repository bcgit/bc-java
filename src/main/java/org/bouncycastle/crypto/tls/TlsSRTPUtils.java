package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Hashtable;

import org.bouncycastle.util.Integers;

/**
 * RFC 5764 DTLS Extension to Establish Keys for SRTP.
 */
public class TlsSRTPUtils {

    public static final Integer EXT_use_srtp = Integers.valueOf(ExtensionType.use_srtp);

    public static class UseSRTPData {

        private int[] protectionProfiles;
        private byte[] mki;

        /**
         * @param protectionProfiles
         *            see {@link SRTPProtectionProfile} for valid constants.
         * @param mki
         *            valid lengths from 0 to 255.
         */
        public UseSRTPData(int[] protectionProfiles, byte[] mki) {

            if (protectionProfiles == null || protectionProfiles.length < 1
                || protectionProfiles.length >= (1 << 15)) {
                throw new IllegalArgumentException(
                    "'protectionProfiles' must have length from 1 to (2^15 - 1)");
            }

            if (mki == null) {
                mki = TlsUtils.EMPTY_BYTES;
            } else if (mki.length > 255) {
                throw new IllegalArgumentException("'mki' cannot be longer than 255 bytes");
            }

            this.protectionProfiles = protectionProfiles;
            this.mki = mki;
        }

        /**
         * @return see {@link SRTPProtectionProfile} for valid constants.
         */
        public int[] getProtectionProfiles() {
            return protectionProfiles;
        }

        /**
         * @return valid lengths from 0 to 255.
         */
        public byte[] getMki() {
            return mki;
        }
    }

    public static void addUseSRTPExtension(Hashtable extensions, UseSRTPData useSRTPData)
        throws IOException {

        extensions.put(EXT_use_srtp, createUseSRTPExtension(useSRTPData));
    }

    public static UseSRTPData getUseSRTPExtension(Hashtable extensions) throws IOException {

        if (extensions == null) {
            return null;
        }
        byte[] extensionValue = (byte[]) extensions.get(EXT_use_srtp);
        if (extensionValue == null) {
            return null;
        }
        return readUseSRTPExtension(extensionValue);
    }

    public static byte[] createUseSRTPExtension(UseSRTPData useSRTPData) throws IOException {

        if (useSRTPData == null) {
            throw new IllegalArgumentException("'useSRTPData' cannot be null");
        }

        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        // SRTPProtectionProfiles
        int[] protectionProfiles = useSRTPData.getProtectionProfiles();
        TlsUtils.writeUint16(2 * protectionProfiles.length, buf);
        TlsUtils.writeUint16Array(protectionProfiles, buf);

        // srtp_mki
        TlsUtils.writeOpaque8(useSRTPData.getMki(), buf);

        return buf.toByteArray();
    }

    public static UseSRTPData readUseSRTPExtension(byte[] extensionValue) throws IOException {

        if (extensionValue == null) {
            throw new IllegalArgumentException("'extensionValue' cannot be null");
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(extensionValue);

        // SRTPProtectionProfiles
        int length = TlsUtils.readUint16(buf);
        if (length < 2 || (length & 1) != 0) {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        int[] protectionProfiles = TlsUtils.readUint16Array(length / 2, buf);

        // srtp_mki
        byte[] mki = TlsUtils.readOpaque8(buf);

        TlsProtocol.assertEmpty(buf);

        return new UseSRTPData(protectionProfiles, mki);
    }
}
