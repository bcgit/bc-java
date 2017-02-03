package org.bouncycastle.est;


import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

class HttpUtil
{

    /**
     * Merge kv into comma separated set of key="value" pairs.
     * @param prefix Optional prefix to apply, eg:  prefix key="value" (,key="value")
     * @param kv
     * @return
     */
     static String mergeCSL(String prefix, Map<String, String> kv)
    {
        StringWriter sw = new StringWriter();
        sw.write(prefix);
        sw.write(' ');
        boolean comma = false;
        for (Map.Entry<String, String> ent : kv.entrySet())
        {
            if (!comma)
            {
                comma = true;
            }
            else
            {
                sw.write(',');
            }

            sw.write(ent.getKey());
            sw.write("=\"");
            sw.write(ent.getValue());
            sw.write('"');
        }

        return sw.toString();
    }


     static Map<String, String> splitCSL(String skip, String src)
    {
        src = src.trim();
        if (src.startsWith(skip))
        {
            src = src.substring(skip.length());
        }

        return new PartLexer(src).Parse();
    }


     static class PartLexer
    {
        private final String src;
        int last = 0;
        int p = 0;

         PartLexer(String src)
        {
            this.src = src;
        }


         Map<String, String> Parse()
        {
            Map<String, String> out = new HashMap<String, String>();
            String key = null;
            String value = null;
            while (p < src.length())
            {
                skipWhiteSpace();

                key = consumeAlpha();
                if (key.length() == 0)
                {
                    throw new IllegalArgumentException("Expecting alpha label.");
                }
                skipWhiteSpace();
                if (!consumeIf('='))
                {
                    throw new IllegalArgumentException("Expecting assign: '='");
                }


                skipWhiteSpace();
                if (!consumeIf('"'))
                {
                    throw new IllegalArgumentException("Expecting start quote: '\"'");
                }
                discard();

                value = consumeUntil('"');
                if (value.length() == 0)
                {
                    throw new IllegalArgumentException("Expecting quoted value.");
                }

                discard(1);
                out.put(key, value);

                skipWhiteSpace();
                if (!consumeIf(','))
                {
                    break;
                }
                discard();
            }

            return out;
        }


        private String consumeAlpha()
        {
            char c = src.charAt(p);
            while (p < src.length() && ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')))
            {
                p++;
                c = src.charAt(p);
            }
            String s = src.substring(last, p);
            last = p;
            return s;
        }

        private void skipWhiteSpace()
        {
            while (p < src.length() && (src.charAt(p) < 33))
            {
                p++;
            }
            last = p;
        }

        private boolean consumeIf(char c)
        {

            if (p < src.length() && src.charAt(p) == c)
            {
                p++;
                return true;
            }
            return false;
        }

        private String consumeUntil(char c)
        {
            while (p < src.length() && (src.charAt(p) != c))
            {
                p++;
            }
            String s = src.substring(last, p);
            last = p;
            return s;
        }

        private void discard()
        {
            last = p;
        }

        private void discard(int i)
        {
            p += i;
            last = p;
        }

    }

}
