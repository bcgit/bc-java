package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * Signature Subpacket for encoding a URI pointing to a document containing the policy under which the
 * signature was created.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.20">
 *     RFC4880 - Policy URI</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-policy-uri">
 *     RFC9580 - Policy URI</a>
 */
public class PolicyURI
    extends SignatureSubpacket
{
    public PolicyURI(boolean critical, boolean isLongLength, byte[] data)
    {
        super(SignatureSubpacketTags.POLICY_URL, critical, isLongLength, data);
    }

    public PolicyURI(boolean critical, String uri)
    {
        this(critical, false, Strings.toUTF8ByteArray(uri));
    }

    public String getURI()
    {
        return Strings.fromUTF8ByteArray(data);
    }

    public byte[] getRawURI()
    {
        return Arrays.clone(data);
    }
}
