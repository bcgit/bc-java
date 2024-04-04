package org.bouncycastle.gpg;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.bouncycastle.openpgp.PGPExtendedKeyAttribute;
import org.bouncycastle.openpgp.PGPRuntimeOperationException;
import org.bouncycastle.util.Characters;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

public class SExpression
{
    //TODO  make immutable.

    private static final Set<Character> labelStop = new HashSet<Character>()
    {{
        add(Characters.valueOf(' '));
        add(Characters.valueOf(')'));
        add(Characters.valueOf('('));
        add(Characters.valueOf('#'));
        add(Characters.valueOf('\"'));
        add(Characters.valueOf(':'));
    }};

    private static final Set<String> stringLabels = new HashSet<String>()
    {
        {
            add("protected");
            add("protected-at");
            add("curve");
        }
    };
    private final ArrayList<Object> values = new ArrayList<Object>();
    private boolean canonical = false;

    private boolean parseCanonical = false;

    public SExpression(List<Object> values)
    {
        this.values.addAll(values);
    }


    public SExpression()
    {

    }

    public static SExpression parse(byte[] src, int maxDepth)
        throws IOException
    {
        return parse(new ByteArrayInputStream(src), maxDepth);
    }

    /**
     * Parser for canonical and normal S-Expressions
     *
     * @param _src     Input
     * @param maxDepth maximum recursion depth before failing
     * @return An SExpression
     * @throws IOException
     */
    public static SExpression parse(InputStream _src, int maxDepth)
        throws IOException
    {
        return parseExpression(_src, null, new ByteArrayOutputStream(), maxDepth);
    }

    private static SExpression parseExpression(InputStream src, SExpression expr, ByteArrayOutputStream accumulator, int maxDepth)
        throws IOException
    {
        if (accumulator == null)
        {
            accumulator = new ByteArrayOutputStream();
        }
        try
        {
            //
            // While we are using the callstack we want to artificially limit depth so
            // a malformed message cannot cause a denial service via the callstack.
            //
            maxDepth--;
            if (maxDepth < 0)
            {
                throw new IllegalStateException("S-Expression exceeded maximum depth");
            }

            int c;
            for (; ; )
            {
                // eg (d\n #ABAB#)
                c = consumeUntilSkipCRorLF(src, accumulator, labelStop);

                if (c == ':')
                {
                    try
                    {
                        int len = Integer.parseInt(Strings.fromByteArray(accumulator.toByteArray()));
                        byte[] b = new byte[len];
                        Streams.readFully(src, b);
                        if (expr.parseCanonical)
                        {
                            int size = expr.values.size();
                            if (size > 0)
                            {
                                Object object = expr.values.get(size - 1);
                                if (object instanceof String && stringLabels.contains(object))
                                {
                                    expr.addValue(Strings.fromUTF8ByteArray(b));
                                }
                                else
                                {
                                    expr.addValue(b);
                                }
                            }
                            else
                            {
                                expr.addValue(Strings.fromUTF8ByteArray(b));
                            }
                        }
                        else
                        {
                            expr.addValue(b);
                            expr.setCanonical(true);
                        }
                    }
                    catch (NumberFormatException e)
                    {
                        expr.addValue(accumulator.toByteArray());
                    }
                    continue;
                }

                if (accumulator.size() > 0)
                {
                    expr.addValue(Strings.fromByteArray(accumulator.toByteArray()));
                }

                if (c == '(')
                {
                    if (expr == null)
                    {
                        expr = new SExpression();
                        parseExpression(src, expr, accumulator, maxDepth);
                        return expr;
                    }
                    else
                    {
                        SExpression subExpression = new SExpression();
                        subExpression.parseCanonical = expr.parseCanonical;
                        expr.addValue(parseExpression(src, subExpression, accumulator, maxDepth));
                    }
                }
                else if (c == '#')
                {
                    consumeUntilSkipWhiteSpace(src, accumulator, '#');
                    expr.addValue(Hex.decode(Strings.fromByteArray(accumulator.toByteArray())));
                }
                else if (c == '"')
                {
                    consumeUntilSkipCRorLF(src, accumulator, '"');
                    expr.addValue(new SExpression.QuotedString(Strings.fromByteArray(accumulator.toByteArray())));
                }
                else if (c == ')')
                {
                    return expr;
                }
                else if (c == -1)
                {
                    break;
                }
            }
        }
        finally
        {
            maxDepth++;
        }

        return expr;

    }

    static SExpression parseCanonical(InputStream _src, int maxDepth)
        throws IOException
    {
        SExpression expr = new SExpression();
        expr.parseCanonical = true;
        return parseExpression(_src, expr, new ByteArrayOutputStream(), maxDepth).getExpression(0);
    }

//    private static void consumeUntil(InputStream src, ByteArrayOutputStream accumulator, char item)
//        throws IOException
//    {
//        accumulator.reset();
//        int c;
//        while ((c = src.read()) > -1)
//        {
//            if (c == item)
//            {
//                return;
//            }
//            accumulator.write(c);
//        }
//    }

    private static void consumeUntilSkipWhiteSpace(InputStream src, ByteArrayOutputStream accumulator, char item)
        throws IOException
    {
        accumulator.reset();
        int c;
        while ((c = src.read()) > -1)
        {
            if (c <= ' ')
            {
                continue;
            }
            if (c == item)
            {
                return;
            }
            accumulator.write(c);
        }
    }

    private static int consumeUntilSkipCRorLF(InputStream src, ByteArrayOutputStream accumulator, Set<Character> characterSet)
        throws IOException
    {
        accumulator.reset();
        int c;
        boolean lineEnd = false;
        while ((c = src.read()) > -1)
        {
            if (lineEnd && c <= 32)
            {
                lineEnd = false;
                continue;
            }

            if (c == '\n')
            {
                lineEnd = true;
                continue;
            }
            if (characterSet.contains(Characters.valueOf((char)c)))
            {
                return c;
            }

            accumulator.write(c);
        }
        return -1;
    }

    private static int consumeUntilSkipCRorLF(InputStream src, ByteArrayOutputStream accumulator, char ch)
        throws IOException
    {
        accumulator.reset();
        int c;
        boolean lineEnd = false;
        while ((c = src.read()) > -1)
        {
            if (lineEnd && c <= 32)
            {
                lineEnd = false;
                continue;
            }

            if (c == '\n')
            {
                lineEnd = true;
                continue;
            }
            if (ch == c)
            {
                return c;
            }

            accumulator.write(c);
        }
        return -1;
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public void addValue(Object value)
    {
        this.values.add(value);
    }

    public Object getValue(int i)
    {
        return values.get(i);
    }

    public String getString(int i)
    {
        Object val = values.get(i);
        if (val instanceof byte[])
        {
            return Strings.fromUTF8ByteArray((byte[])val);
        }

        return values.get(i).toString();
    }

    public int getInt(int i)
    {
        return Integer.parseInt(getString(i));
    }

    public byte[] getBytes(int i)
    {
        return (byte[])values.get(i);
    }

    public SExpression getExpression(int i)
    {
        return (SExpression)values.get(i);
    }

    public List<Object> getValues()
    {
        return values;
    }

    public boolean isCanonical()
    {
        return canonical;
    }

    private void setCanonical(boolean canonical)
    {
        this.canonical = canonical;
    }

    public PGPExtendedKeyAttribute toAttribute()
    {

        PGPExtendedKeyAttribute.Builder builder = PGPExtendedKeyAttribute.builder();
        for (Iterator it = values.iterator(); it.hasNext(); )
        {
            builder.addAttribute(it.next());
        }
        return builder.build();
    }

    public SExpression filterOut(String... keys)
    {

        HashSet<String> set = new HashSet<String>();
        set.addAll(Arrays.asList(keys));

        SExpression expr = new SExpression();
        for (Iterator it = values.iterator(); it.hasNext(); )
        {
            Object item = it.next();
            if (set.contains(item.toString()))
            {
                continue;
            }

            if (item instanceof SExpression)
            {
                if (!((SExpression)item).values.isEmpty())
                {
                    String label = ((SExpression)item).values.get(0).toString();
                    if (set.contains(label))
                    {
                        continue;
                    }
                }
                expr.values.add(((SExpression)item).filterOut(keys));
            }
            else
            {
                expr.values.add(item);
            }
        }
        return expr;
    }

    /**
     * This function expects the labels is in order
     */
    static SExpression buildExpression(SExpression expression, String[] labels)
    {
        SExpression rlt = new SExpression();
        rlt.addValue(labels[0]);
        for (int i = 1; i < labels.length; ++i)
        {
            SExpression item = expression.getExpressionWithLabel(labels[i]);
            if (item != null)
            {
                rlt.values.add(item);
            }
        }
        return rlt;
    }

    static SExpression buildExpression(SExpression expr1, SExpression expr2, String[] labels)
    {
        SExpression rlt = new SExpression();
        rlt.addValue(labels[0]);
        for (int i = 1; i < labels.length; ++i)
        {
            SExpression item = expr1.getExpressionWithLabel(labels[i]);
            if (item != null)
            {
                rlt.values.add(item);
            }
            else
            {
                item = expr2.getExpressionWithLabel(labels[i]);
                if (item != null)
                {
                    rlt.values.add(item);
                }
            }
        }
        return rlt;
    }

    public SExpression filterIn(String... keys)
    {

        HashSet<String> set = new HashSet<String>();
        set.addAll(Arrays.asList(keys));

        SExpression expr = new SExpression();
        for (Iterator it = values.iterator(); it.hasNext(); )
        {
            Object item = it.next();
            if (item instanceof SExpression)
            {
                if (!((SExpression)item).values.isEmpty())
                {
                    String label = ((SExpression)item).values.get(0).toString();
                    if (!set.contains(label))
                    {
                        continue;
                    }
                }
                expr.values.add(item);
            }
            else
            {

                if (!set.contains(item.toString()))
                {
                    continue;
                }


                expr.values.add(item);
            }
        }
        return expr;
    }

    public byte[] toCanonicalForm()
    {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try
        {
            toCanonicalForm(bos);
        }
        catch (Exception ex)
        {
            throw new PGPRuntimeOperationException(ex.getMessage(), ex);
        }
        return bos.toByteArray();
    }

    public void toCanonicalForm(OutputStream out)
        throws IOException
    {
        out.write('(');
        for (Iterator it = values.iterator(); it.hasNext(); )
        {
            Object value = it.next();
            if (value instanceof QuotedString)
            {
                String s = ((QuotedString)value).value;
                out.write(Strings.toByteArray(Integer.toString(s.length())));
                out.write(':');
                out.write(Strings.toUTF8ByteArray(s));
            }
            else if (value instanceof String)
            {
                String s = (String)value;
                out.write(Strings.toByteArray(Integer.toString(s.length())));
                out.write(':');
                out.write(Strings.toUTF8ByteArray(s));
            }
            else if (value instanceof byte[])
            {
                byte[] b = ((byte[])value);
                out.write(Strings.toByteArray(Integer.toString(b.length)));
                out.write(':');
                out.write(b);
            }
            else if (value instanceof SExpression)
            {
                ((SExpression)value).toCanonicalForm(out);
            }
            else
            {
                throw new IllegalStateException("unhandled type " + value.getClass().getName() + " in value list");
            }
        }
        out.write(')');
        out.flush();
    }

    public boolean hasLabel(String label)
    {
        if (values.isEmpty())
        {
            throw new IllegalArgumentException("S-Expression is empty");
        }
        Object val = values.get(0);
        if (val instanceof String || val instanceof QuotedString)
        {
            val = val.toString();
        }
        else
        {
            val = Strings.fromByteArray((byte[])val);
        }
        return val.equals(label);
    }

    public SExpression getExpressionWithLabel(String label)
    {
        for (Iterator it = values.iterator(); it.hasNext(); )
        {
            Object o = it.next();
            if (o instanceof SExpression)
            {
                if (((SExpression)o).hasLabel(label))
                {
                    return (SExpression)o;
                }
            }
        }
        return null;
    }

    public SExpression getExpressionWithLabelOrFail(String label)
    {
        for (Iterator it = values.iterator(); it.hasNext(); )
        {
            Object o = it.next();
            if (o instanceof SExpression)
            {
                if (((SExpression)o).hasLabel(label))
                {
                    return (SExpression)o;
                }
            }
        }
        throw new IllegalArgumentException("label " + label + " was not found");
    }

    public static class QuotedString
    {
        private final String value;

        public QuotedString(String value)
        {
            this.value = value;
        }

        public String toString()
        {
            return value;
        }
    }

    public static class Builder
    {
        List<Object> values = new ArrayList<Object>();

        public Builder addValue(Object value)
        {
            values.add(value);
            return this;
        }

        public SExpression build()
        {
            return new SExpression(values);
        }

        public Builder addContent(SExpression other)
        {
            for (Iterator it = other.values.iterator(); it.hasNext(); )
            {
                values.add(it.next());
            }

            return this;
        }

    }
}
