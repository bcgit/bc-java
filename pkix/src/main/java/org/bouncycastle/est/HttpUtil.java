package org.bouncycastle.est;


import java.io.StringWriter;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

class HttpUtil
{

    /**
     * Merge kv into comma separated set of key="value" pairs.
     *
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
        for (Iterator it = kv.entrySet().iterator(); it.hasNext();)
        {
            Map.Entry<String, String> ent = (Map.Entry<String, String>)it.next();

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

    static class Headers
        extends HashMap<String, String[]>
    {
        public Headers()
        {
            super();
        }

        public String getFirstValue(String key)
        {
            String[] j = getValues(key);
            if (j != null && j.length > 0)
            {
                return j[0];
            }
            return null;
        }

        public String[] getValues(String key)
        {
            key = actualKey(key);
            if (key == null)
            {
                return null;
            }
            return get(key);
        }

        private String actualKey(String header)
        {
            if (containsKey(header))
            {
                return header;
            }

            for (Iterator it = keySet().iterator(); it.hasNext();)
            {
                String k = (String)it.next();
                if (header.equalsIgnoreCase(k))
                {
                    return k;
                }
            }

            return null;
        }

        private boolean hasHeader(String header)
        {
            return actualKey(header) != null;
        }


        public void set(String key, String value)
        {
            put(key, new String[]{value});
        }

        public void add(String key, String value)
        {
            put(key, append(get(key), value));
        }

        public void ensureHeader(String key, String value)
        {
            if (!containsKey(key))
            {
                set(key, value);
            }
        }
        
        public Object clone()
        {
            Headers n = new Headers();
            for (Iterator it = entrySet().iterator(); it.hasNext();)
            {
                Map.Entry v = (Map.Entry)it.next();

                n.put((String)v.getKey(), copy((String[])v.getValue()));
            }
            return n;
        }

        private String[] copy(String[] vs)
        {
            String[] rv = new String[vs.length];

            System.arraycopy(vs, 0, rv, 0, rv.length);
            
            return rv;
        }
    }


    public static String[] append(String[] a, String b)
    {
        if (a == null)
        {
            return new String[]{b};
        }

        int length = a.length;
        String[] result = new String[length + 1];
        System.arraycopy(a, 0, result, 0, length);
        result[length] = b;
        return result;
    }

}
