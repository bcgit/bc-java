package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * Signature Subpacket containing the URI of the users preferred key server.
 * This is a URI of a key server that the key holder prefers be used for updates.
 * Note that keys with multiple User IDs can have a preferred key server for each User ID.
 * Note also that since this is a URI, the key server can actually be a copy of the key
 * retrieved by ftp, http, finger, etc.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.18">
 *     RFC4880 - Preferred Key Server</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-preferred-key-server">
 *     RFC9580 - Preferred Key Server</a>
 */
public class PreferredKeyServer
        extends SignatureSubpacket
{
    public PreferredKeyServer(boolean critical, boolean isLongLength, byte[] data)
    {
        super(SignatureSubpacketTags.PREFERRED_KEY_SERV, critical, isLongLength, data);
    }

    public PreferredKeyServer(boolean critical, String uri)
    {
        this(critical, false, Strings.toUTF8ByteArray(uri));
    }

    /**
     * Return the URI of the users preferred key server.
     * @return key server uri
     */
    public String getURI()
    {
        return Strings.fromUTF8ByteArray(data);
    }

    public byte[] getRawURI()
    {
        return Arrays.clone(data);
    }
}
