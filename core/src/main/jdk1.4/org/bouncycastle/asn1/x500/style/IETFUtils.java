package org.bouncycastle.asn1.x500.style;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1UniversalString;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class IETFUtils
{
    private static String unescape(String elt)
    {
        if (elt.length() == 0)
        {
            return elt;
        }
        if (elt.indexOf('\\') < 0 && elt.indexOf('"') < 0)
        {
            return elt.trim();
        }

        boolean escaped = false;
        boolean quoted = false;
        StringBuffer buf = new StringBuffer(elt.length());
        int start = 0;

        // if it's an escaped hash string and not an actual encoding in string form
        // we need to leave it escaped.
        if (elt.charAt(0) == '\\')
        {
            if (elt.charAt(1) == '#')
            {
                start = 2;
                buf.append("\\#");
            }
        }

        boolean nonWhiteSpaceEncountered = false;
        int     lastEscaped = 0;
        char    hex1 = 0;

        for (int i = start; i != elt.length(); i++)
        {
            char c = elt.charAt(i);

            if (c != ' ')
            {
                nonWhiteSpaceEncountered = true;
            }

            if (c == '"')
            {
                if (!escaped)
                {
                    quoted = !quoted;
                }
                else
                {
                    buf.append(c);
                    escaped = false;
                }
            }
            else if (c == '\\' && !(escaped || quoted))
            {
                escaped = true;
                lastEscaped = buf.length();
            }
            else
            {
                if (c == ' ' && !escaped && !nonWhiteSpaceEncountered)
                {
                    continue;
                }
                if (escaped && isHexDigit(c))
                {
                    if (hex1 != 0)
                    {
                        buf.append((char)(convertHex(hex1) * 16 + convertHex(c)));
                        escaped = false;
                        hex1 = 0;
                        continue;
                    }
                    hex1 = c;
                    continue;
                }
                buf.append(c);
                escaped = false;
            }
        }

        if (buf.length() > 0)
        {
            while (buf.charAt(buf.length() - 1) == ' ' && lastEscaped != (buf.length() - 1))
            {
                buf.setLength(buf.length() - 1);
            }
        }

        return buf.toString();
    }

    private static boolean isHexDigit(char c)
    {
        return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F');
    }

    private static int convertHex(char c)
    {
        if ('0' <= c && c <= '9')
        {
            return c - '0';
        }
        if ('a' <= c && c <= 'f')
        {
            return c - 'a' + 10;
        }
        return c - 'A' + 10;
    }

    public static RDN[] rDNsFromString(String name, X500NameStyle x500Style)
    {
        X500NameTokenizer tokenizer = new X500NameTokenizer(name);
        X500NameBuilder builder = new X500NameBuilder(x500Style);

        addRDNs(x500Style, builder, tokenizer);

        // TODO There's an unnecessary clone of the RDNs array happening here
        return builder.build().getRDNs();
    }

    private static void addRDNs(X500NameStyle style, X500NameBuilder builder, X500NameTokenizer tokenizer)
    {
        String token;
        while ((token = tokenizer.nextToken()) != null)
        {
            if (token.indexOf('+') >= 0)
            {
                addMultiValuedRDN(style, builder, new X500NameTokenizer(token, '+'));
            }
            else
            {
                addRDN(style, builder, token);
            }
        }
    }

    private static void addMultiValuedRDN(X500NameStyle style, X500NameBuilder builder, X500NameTokenizer tokenizer)
    {
        String token = tokenizer.nextToken();
        if (token == null)
        {
            throw new IllegalArgumentException("badly formatted directory string");
        }

        if (!tokenizer.hasMoreTokens())
        {
            addRDN(style, builder, token);
            return;
        }

        Vector oids = new Vector();
        Vector values = new Vector();

        do
        {
            collectAttributeTypeAndValue(style, oids, values, token);
            token = tokenizer.nextToken();
        }
        while (token != null);

        builder.addMultiValuedRDN(toOIDArray(oids), toValueArray(values));
    }

    private static void addRDN(X500NameStyle style, X500NameBuilder builder, String token)
    {
        X500NameTokenizer tokenizer = new X500NameTokenizer(token, '=');

        String typeToken = nextToken(tokenizer, true);
        String valueToken = nextToken(tokenizer, false);

        ASN1ObjectIdentifier oid = style.attrNameToOID(typeToken.trim());
        String value = unescape(valueToken);

        builder.addRDN(oid, value);
    }

    private static void collectAttributeTypeAndValue(X500NameStyle style, Vector oids, Vector values, String token)
    {
        X500NameTokenizer tokenizer = new X500NameTokenizer(token, '=');

        String typeToken = nextToken(tokenizer, true);
        String valueToken = nextToken(tokenizer, false);

        ASN1ObjectIdentifier oid = style.attrNameToOID(typeToken.trim());
        String value = unescape(valueToken);

        oids.addElement(oid);
        values.addElement(value);
    }

    private static String nextToken(X500NameTokenizer tokenizer, boolean expectMoreTokens)
    {
        String token = tokenizer.nextToken();
        if (token == null || tokenizer.hasMoreTokens() != expectMoreTokens)
        {
            throw new IllegalArgumentException("badly formatted directory string");
        }
        return token;
    }

    private static String[] toValueArray(Vector values)
    {
        String[] tmp = new String[values.size()];

        for (int i = 0; i != tmp.length; i++)
        {
            tmp[i] = (String)values.elementAt(i);
        }

        return tmp;
    }

    private static ASN1ObjectIdentifier[] toOIDArray(Vector oids)
    {
        ASN1ObjectIdentifier[] tmp = new ASN1ObjectIdentifier[oids.size()];

        for (int i = 0; i != tmp.length; i++)
        {
            tmp[i] = (ASN1ObjectIdentifier)oids.elementAt(i);
        }

        return tmp;
    }

    public static String[] findAttrNamesForOID(
        ASN1ObjectIdentifier oid,
        Hashtable            lookup)
    {
        int count = 0;
        for (Enumeration en = lookup.elements(); en.hasMoreElements();)
        {
            if (oid.equals(en.nextElement()))
            {
                count++;
            }
        }

        String[] aliases = new String[count];
        count = 0;

        for (Enumeration en = lookup.keys(); en.hasMoreElements();)
        {
            String key = (String)en.nextElement();
            if (oid.equals(lookup.get(key)))
            {
                aliases[count++] = key;
            }
        }

        return aliases;
    }

    public static ASN1ObjectIdentifier decodeAttrName(String name, Hashtable lookUp)
    {
        if (name.regionMatches(true, 0, "OID.", 0, 4))
        {
            return new ASN1ObjectIdentifier(name.substring(4));
        }

        ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.tryFromID(name);
        if (oid != null)
        {
            return oid;
        }

        oid = (ASN1ObjectIdentifier)lookUp.get(Strings.toLowerCase(name));
        if (oid != null)
        {
            return oid;
        }

        throw new IllegalArgumentException("Unknown object id - " + name + " - passed to distinguished name");
    }

    public static ASN1Encodable valueFromHexString(
        String  str,
        int     off)
        throws IOException
    {
        byte[] data = new byte[(str.length() - off) / 2];
        for (int index = 0; index != data.length; index++)
        {
            char left = str.charAt((index * 2) + off);
            char right = str.charAt((index * 2) + off + 1);

            data[index] = (byte)((convertHex(left) << 4) | convertHex(right));
        }

        return ASN1Primitive.fromByteArray(data);
    }

    public static void appendRDN(
        StringBuffer          buf,
        RDN                   rdn,
        Hashtable             oidSymbols)
    {
        if (rdn.isMultiValued())
        {
            AttributeTypeAndValue[] atv = rdn.getTypesAndValues();
            boolean firstAtv = true;

            for (int j = 0; j != atv.length; j++)
            {
                if (firstAtv)
                {
                    firstAtv = false;
                }
                else
                {
                    buf.append('+');
                }

                IETFUtils.appendTypeAndValue(buf, atv[j], oidSymbols);
            }
        }
        else
        {
            if (rdn.getFirst() != null)
            {
                IETFUtils.appendTypeAndValue(buf, rdn.getFirst(), oidSymbols);
            }
        }
    }

    public static void appendTypeAndValue(
        StringBuffer          buf,
        AttributeTypeAndValue typeAndValue,
        Hashtable             oidSymbols)
    {
        String  sym = (String)oidSymbols.get(typeAndValue.getType());

        if (sym != null)
        {
            buf.append(sym);
        }
        else
        {
            buf.append(typeAndValue.getType().getId());
        }

        buf.append('=');

        buf.append(valueToString(typeAndValue.getValue()));
    }

    public static String valueToString(ASN1Encodable value)
    {
        StringBuffer vBuf = new StringBuffer();

        if (value instanceof ASN1String && !(value instanceof ASN1UniversalString))
        {
            String v = ((ASN1String)value).getString();
            if (v.length() > 0 && v.charAt(0) == '#')
            {
                vBuf.append('\\');
            }

            vBuf.append(v);
        }
        else
        {
            try
            {
                vBuf.append('#');
                // -DM Hex.toHexString
                vBuf.append(Hex.toHexString(value.toASN1Primitive().getEncoded(ASN1Encoding.DER)));
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("Other value has no encoded form");
            }
        }

        int end = vBuf.length();
        int index = 0;

        if (vBuf.length() >= 2 && vBuf.charAt(0) == '\\' && vBuf.charAt(1) == '#')
        {
            index += 2;
        }

        while (index != end)
        {
            switch (vBuf.charAt(index))
            {
                case ',':
                case '"':
                case '\\':
                case '+':
                case '=':
                case '<':
                case '>':
                case ';':
                {
                    vBuf.insert(index, "\\");
                    index += 2;
                    ++end;
                    break;
                }
                default:
                {
                    ++index;
                    break;
                }
            }
        }

        int start = 0;
        if (vBuf.length() > 0)
        {
            while (vBuf.length() > start && vBuf.charAt(start) == ' ')
            {
                vBuf.insert(start, "\\");
                start += 2;
            }
        }

        int endBuf = vBuf.length() - 1;

        while (endBuf >= start && vBuf.charAt(endBuf) == ' ')
        {
            vBuf.insert(endBuf, '\\');
            endBuf--;
        }

        return vBuf.toString();
    }

    public static String canonicalize(String s)
    {
        if (s.length() > 0 && s.charAt(0) == '#')
        {
            ASN1Primitive obj = decodeObject(s);
            if (obj instanceof ASN1String)
            {
                s = ((ASN1String)obj).getString();
            }
        }

        s = Strings.toLowerCase(s);

        int length = s.length();
        if (length < 2)
        {
            return s;
        }

        int start = 0, last = length - 1;
        while (start < last && s.charAt(start) == '\\' && s.charAt(start + 1) == ' ')
        {
            start += 2;
        }

        int end = last, first = start + 1;
        while (end > first && s.charAt(end - 1) == '\\' && s.charAt(end) == ' ')
        {
            end -= 2;
        }

        if (start > 0 || end < last)
        {
            s = s.substring(start, end + 1);
        }

        return stripInternalSpaces(s);
    }

    public static String canonicalString(ASN1Encodable value)
    {
        return canonicalize(valueToString(value));
    }

    private static ASN1Primitive decodeObject(String oValue)
    {
        try
        {
            return ASN1Primitive.fromByteArray(Hex.decodeStrict(oValue, 1, oValue.length() - 1));
        }
        catch (IOException e)
        {
            throw new IllegalStateException("unknown encoding in name: " + e);
        }
    }

    public static String stripInternalSpaces(
        String str)
    {
        if (str.indexOf("  ") < 0)
        {
            return str;
        }

        StringBuffer res = new StringBuffer();

        char c1 = str.charAt(0);
        res.append(c1);

        for (int k = 1; k < str.length(); k++)
        {
            char c2 = str.charAt(k);
            if (!(c1 == ' ' && c2 == ' '))
            {
                res.append(c2);
                c1 = c2;
            }
        }

        return res.toString();
    }

    public static boolean rDNAreEqual(RDN rdn1, RDN rdn2)
    {
        if (rdn1.size() != rdn2.size())
        {
            return false;
        }

        AttributeTypeAndValue[] atvs1 = rdn1.getTypesAndValues();
        AttributeTypeAndValue[] atvs2 = rdn2.getTypesAndValues();

        if (atvs1.length != atvs2.length)
        {
            return false;
        }

        for (int i = 0; i != atvs1.length; i++)
        {
            if (!atvAreEqual(atvs1[i], atvs2[i]))
            {
                return false;
            }
        }

        return true;
    }

    private static boolean atvAreEqual(AttributeTypeAndValue atv1, AttributeTypeAndValue atv2)
    {
        if (atv1 == atv2)
        {
            return true;
        }

        if (null == atv1 || null == atv2)
        {
            return false;
        }

        ASN1ObjectIdentifier o1 = atv1.getType();
        ASN1ObjectIdentifier o2 = atv2.getType();

        if (!o1.equals(o2))
        {
            return false;
        }

        String v1 = canonicalString(atv1.getValue());
        String v2 = canonicalString(atv2.getValue());

        if (!v1.equals(v2))
        {
            return false;
        }

        return true;
    }
}
