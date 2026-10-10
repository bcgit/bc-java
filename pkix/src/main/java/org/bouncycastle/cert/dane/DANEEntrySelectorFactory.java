package org.bouncycastle.cert.dane;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Factory for creating selector objects to use with the DANECertificateStore.
 */
public class DANEEntrySelectorFactory
{
    private final DigestCalculator digestCalculator;

    /**
     * Base constructor.
     * <p>
     * At the moment you would call this as:
     * <pre>
     *     new DANEEntrySelectorFactory(new TruncatingDigestCalculator(new SHA256DigestCalculator()));
     * </pre>
     * or some equivalent.
     *
     * @param digestCalculator a calculator for the message digest to filter email addresses currently truncated SHA-256 (originally SHA-224).
     */
    public DANEEntrySelectorFactory(DigestCalculator digestCalculator)
    {
        this.digestCalculator = digestCalculator;
    }

    /**
     * Create a selector for the passed in email address.
     * <p>
     * The owner name is formed as in RFC 8162 sec. 3: the local-part, with any enclosing double quotes and
     * backslash quoting removed, is hashed with the digest calculator and the hex result becomes the left-most
     * label, followed by "_smimecert" and the domain. No case mapping is applied to the local-part (RFC 8162
     * sec. 4) and comments or folding whitespace in it are not removed.
     *
     * @param emailAddress the emails address of interest.
     * @throws DANEException in case of issue generating a matching name.
     */
    public DANEEntrySelector createSelector(String emailAddress)
        throws DANEException
    {
        int atIndex = emailAddress.lastIndexOf('@');
        if (atIndex < 0)
        {
            throw new DANEException("email address has no '@'");
        }

        final byte[] enc = Strings.toUTF8ByteArray(unquoteLocalPart(emailAddress.substring(0, atIndex)));

        try
        {
            OutputStream cOut = digestCalculator.getOutputStream();

            cOut.write(enc);

            cOut.close();
        }
        catch (IOException e)
        {
            throw new DANEException("Unable to calculate digest string: " + e.getMessage(), e);
        }

        byte[] hash = digestCalculator.getDigest();

        final String domainName = Strings.fromByteArray(Hex.encode(hash)) + "._smimecert." + emailAddress.substring(atIndex + 1);

        return new DANEEntrySelector(domainName);
    }

    private static String unquoteLocalPart(String localPart)
    {
        if (localPart.length() < 2 || localPart.charAt(0) != '"' || localPart.charAt(localPart.length() - 1) != '"')
        {
            return localPart;
        }

        StringBuilder sb = new StringBuilder(localPart.length());

        for (int i = 1; i < localPart.length() - 1; i++)
        {
            char c = localPart.charAt(i);
            if (c == '\\' && i + 1 < localPart.length() - 1)
            {
                c = localPart.charAt(++i);
            }
            sb.append(c);
        }

        return sb.toString();
    }
}
