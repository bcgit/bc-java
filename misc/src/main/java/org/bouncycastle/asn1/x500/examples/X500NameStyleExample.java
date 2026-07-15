package org.bouncycastle.asn1.x500.examples;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

/**
 * Example showing how to build an {@link X500NameStyle} that will parse a
 * string-form Distinguished Name whose commonName (CN) value is longer than the
 * RFC 5280 / X.520 upper bound of 64 characters.
 * <p>
 * Background: RFC 5280 sec. A.1 (and X.520) define commonName as a
 * DirectoryString bounded by {@code ub-common-name = 64}, so the default
 * {@link BCStyle} rejects a longer CN at build time -
 * {@code new X500Name("CN=&lt;80 chars&gt;")} throws
 * {@code IllegalArgumentException} from {@code BCStyle.encodeStringValue}
 * (github #750). Note this only affects <b>building</b> a name from its string
 * form; the DER parse path ({@code X500Name.getInstance(byte[])}) never routes
 * through {@code encodeStringValue}, so an already-encoded name with an 80-char
 * CN is read back regardless of style.
 * </p>
 * <p>
 * The style below subclasses {@link BCStyle} and overrides only the CN length
 * cap, raising it to 80 characters while leaving every other attribute's
 * encoding (and the standard 64-char cap for other DirectoryString attributes)
 * exactly as the default. Because it is a full {@link X500NameStyle}, the same
 * instance can be handed to {@code new X500Name(style, dirName)} for parsing and
 * to {@code X500Name.getInstance(style, obj)} for canonical comparison /
 * {@code toString}.
 * </p>
 */
public class X500NameStyleExample
{
    /**
     * The upper bound this style permits for the commonName attribute.
     */
    private static final int MAX_CN_LENGTH = 80;

    /**
     * A style identical to {@link BCStyle} except that commonName may be up to
     * {@link #MAX_CN_LENGTH} characters instead of the RFC 5280 default of 64.
     */
    public static class LongCNStyle
        extends BCStyle
    {
        public static final X500NameStyle INSTANCE = new LongCNStyle();

        protected LongCNStyle()
        {
        }

        protected ASN1Encodable encodeStringValue(ASN1ObjectIdentifier oid, String value)
        {
            if (oid.equals(CN))
            {
                if (value.length() > MAX_CN_LENGTH)
                {
                    throw new IllegalArgumentException("commonName length "
                        + value.length() + " exceeds permitted maximum (" + MAX_CN_LENGTH + "): '" + value + "'");
                }

                // encode directly, bypassing BCStyle's 64-char cap; a CN is a
                // DirectoryString, and BC's default DirectoryString encoding is
                // a UTF8String (as done by AbstractX500NameStyle for all other
                // string-valued attributes).
                return new DERUTF8String(value);
            }

            // every other attribute keeps the standard BCStyle behaviour,
            // including the country-code and other DirectoryString bounds.
            return super.encodeStringValue(oid, value);
        }
    }

    public static void main(String[] args)
    {
        // an 80-character common name
        String longCN = "This Is A Deliberately Very Long Common Name Used To Exceed Sixty Four Character";

        // sanity: exactly 80 characters
        System.out.println("CN length: " + longCN.length());

        String dirName = "CN=" + longCN + ",O=Example Org,C=AU";

        // 1. The default style rejects the long CN when parsing the string form.
        try
        {
            X500Name rejected = new X500Name(BCStyle.INSTANCE, dirName);

            System.out.println("UNEXPECTED: default BCStyle accepted it: " + rejected);
        }
        catch (IllegalArgumentException e)
        {
            System.out.println("default BCStyle rejected long CN, as expected: " + e.getMessage());
        }

        // 2. The custom style parses the same string form successfully.
        X500Name name = new X500Name(LongCNStyle.INSTANCE, dirName);

        System.out.println("custom style parsed name: " + name);

        // 3. It round-trips through DER and reads back with any style, since the
        //    DER parse path does not enforce the length cap.
        try
        {
            byte[] encoded = name.getEncoded();
            X500Name decoded = X500Name.getInstance(encoded);

            String decodedCN = IETFUtils.valueToString(
                decoded.getRDNs(BCStyle.CN)[0].getFirst().getValue());

            System.out.println("re-decoded (default style): " + decoded);
            System.out.println("CN survived round-trip    : " + longCN.equals(decodedCN));
        }
        catch (Exception e)
        {
            throw new IllegalStateException("round-trip failed", e);
        }
    }
}
