package org.bouncycastle.asn1;

/**
 * Class for breaking up an OID into it's component tokens, ala
 * java.util.StringTokenizer. We need this class as some of the
 * lightweight Java environment don't support classes like
 * StringTokenizer.
 */
public class OIDTokenizer
{
    private String  oid;
    private int     index;

    /**
     * Base constructor.
     *
     * @param oid the string representation of the OID.
     */
    public OIDTokenizer(
        String oid)
    {
        this.oid = oid;
        this.index = 0;
    }

    /**
     * Return whether or not there are more tokens in this tokenizer.
     *
     * @return true if there are more tokens, false otherwise.
     */
    public boolean hasMoreTokens()
    {
        return (index != -1);
    }

    /**
     * Return the next token in the underlying String.
     *
     * @return the next token.
     */
    public String nextToken()
    {
        if (index == -1)
        {
            return null;
        }

        String  token;
        int     end = oid.indexOf('.', index);

        if (end == -1)
        {
            token = oid.substring(index);
            index = -1;
            return token;
        }

        token = oid.substring(index, end);

        index = end + 1;
        return token;
    }
}
