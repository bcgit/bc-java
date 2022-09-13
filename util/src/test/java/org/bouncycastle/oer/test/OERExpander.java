package org.bouncycastle.oer.test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.oer.Element;
import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.OEROptional;
import org.bouncycastle.oer.SwitchIndexer;
import org.bouncycastle.util.encoders.Hex;

public class OERExpander
{


    public static Map<String, Set<String>> choiceOptionsAlreadySelected = new HashMap<String, Set<String>>();
    private int depth;
    private int maxDepth = 20;

    public OERExpander(int maxDepth)
    {
        this.maxDepth = maxDepth;
    }

    public static Set<ASN1Encodable> expandElement(Element e)
    {
        OERExpander expander = new OERExpander(100);
        return expander.expand(e);
    }


    public Set<ASN1Encodable> expand(Element e)
    {
        depth = 0;
        Populate populate = makePopulate(e, false);
        LinkedHashSet<ASN1Encodable> uniqueItems = new LinkedHashSet<ASN1Encodable>();
        int t = -1;
        do
        {
            t++;
            ASN1Encodable enc = populate.populate(t, null);
            uniqueItems.add(enc);
        }
        while (!populate.isFinished(t));
        return uniqueItems;
    }

    public Populate makePopulate(Element e, boolean optional)
    {
        try
        {
            depth++;
            if (depth >= maxDepth)
            {
                throw new OERExpanderDepthException(e, true);
            }

            if (optional)
            {
                return new PopulateOptional(e, makePopulate(e, false));
            }


            // Deal with deferred definitions.
            e = Element.expandDeferredDefinition(e, null); // TODO fix

            switch (e.getBaseType())
            {

            case SEQ:
                return new SeqPopulate(e);
            case SEQ_OF:
                return new SeqOfPopulate(e);
            case CHOICE:
                return new ChoicePopulate(e);
            case ENUM:
                return new EnumPopulate(e);
            case INT:
                return new IntPopulate(e);
            case OCTET_STRING:
                return new OctetStringPopulate(e);
            case UTF8_STRING:
                return new TextStringPopulate(e, e.getBaseType());
            case BIT_STRING:
                return new BitStringPopulate(e);
            case NULL:
                return new NullPopulate(e);
            case BOOLEAN:
                return new BooleanPopulate(e);
            case IS0646String:
                break;
            case PrintableString:
                break;
            case NumericString:
                break;
            case BMPString:
                break;
            case UniversalString:
                break;
            case IA5String:
                return new TextStringPopulate(e, e.getBaseType());
            case VisibleString:
                break;
            case EXTENSION:
                return new ExtensionPopulate(e);
            case Switch:
                return new SwitchPopulate(e);
            }
            throw new IllegalStateException("Unhandled bad type " + e.getBaseType().name());

        }
        finally
        {
            depth--;
        }
    }


    public class SwitchPopulate
        implements Populate
    {

        private final Map<ArrayOfAsn1, Populate> populateMap = new HashMap<ArrayOfAsn1, Populate>();
        private Populate lastPopulate = null;
        private final Element def;

        public SwitchPopulate(Element def)
        {
            this.def = def;
        }


        public boolean isFinished(int tick)
        {
            if (lastPopulate == null)
            {
                return false;
            }
            return lastPopulate.isFinished(tick);
        }

        public ASN1Encodable populate(int tick, final ASN1Encodable[] priorValues)
        {
            ArrayOfAsn1 key = new ArrayOfAsn1(priorValues);

            lastPopulate = populateMap.get(key);
            if (lastPopulate == null)
            {
                lastPopulate = makePopulate(def.getaSwitch().result(new SwitchIndexer()
                {

                    public ASN1Encodable get(int index)
                    {
                        return priorValues[index];
                    }
                }), !def.isExplicit());
                populateMap.put(key, lastPopulate);
            }

            return lastPopulate.populate(tick, priorValues);
        }
    }


    public class SeqPopulate
        implements Populate
    {

        private final Element def;

        List<Populate> script = new ArrayList<Populate>();

        public SeqPopulate(Element def)
        {
            this.def = def;
            List<Element> children = def.getChildren();
            for (Element e : children)
            {
                if (e.getBaseType() != OERDefinition.BaseType.EXTENSION)
                {
                    script.add(makePopulate(e, !e.isExplicit()));
                }
            }
        }


        public boolean isFinished(int tick)
        {
            for (Populate p : script)
            {
                if (!p.isFinished(tick))
                {
                    return false;
                }
            }

            return true;
        }

        public ASN1Encodable populate(int tick, ASN1Encodable[] priorValues)
        {

            ASN1Encodable[] values = new ASN1Encodable[script.size()];

            for (int t = 0; t < script.size(); t++)
            {
                values[t] = script.get(t).populate(tick, values);
            }

            return new DERSequence(values);
        }
    }


    public class ChoicePopulate
        implements Populate
    {

        public String toString()
        {
            return "ChoicePopulate{" +
                "def=" + def +
                '}';
        }

        private final Element def;
        private int cnt = 0;
        List<Populate> script = new ArrayList<Populate>();
        List<Integer> choices = new ArrayList<Integer>();

        public ChoicePopulate(Element def)
        {
            this.def = def;

            List<Element> children = def.getChildren();

            for (int choice = 0; choice < children.size(); choice++)
            {
                Element e = children.get(choice);
                if (e.getBaseType() == OERDefinition.BaseType.EXTENSION)
                {
                    continue;
                }

                e = Element.expandDeferredDefinition(e, def);

                if (e.isMayRecurse())
                {
                    if (!choiceOptionsAlreadySelected.containsKey(def.toString()))
                    {
                        HashSet<String> set = new HashSet<String>();
                        set.add(e.toString());
                        choiceOptionsAlreadySelected.put(def.toString(), set);
                    }
                    else
                    {
                        if (choiceOptionsAlreadySelected.get(def.toString()).contains(e.toString()))
                        {
                            continue;
                        }
                    }
                }


                if (e.getBaseType() == OERDefinition.BaseType.EXTENSION)
                {
                    choices.add(choice);
                    script.add(new ExtensionPopulate(e)); // Choices have their extensions tested
                }
                else
                {
                    choices.add(choice);
                    script.add(makePopulate(e, false));
                }
            }
        }


        public boolean isFinished(int tick)
        {
            for (Populate p : script)
            {
                if (!p.isFinished(tick))
                {
                    return false;
                }
            }

            return cnt == script.size();
        }


        public ASN1Encodable populate(int tick, ASN1Encodable[] priorValues)
        {
            if (cnt >= script.size())
            {
                cnt = 0;
            }

            return new DERTaggedObject(choices.get(cnt), script.get(cnt++).populate(tick, null));
        }
    }

    public static class EnumPopulate
        implements Populate
    {
        private final Element def;
        private int cnt = 0;
        List<ASN1Encodable> script = new ArrayList<ASN1Encodable>();

        public EnumPopulate(Element def)
        {
            this.def = def;
            int i = 0;

            if (def.getValidSwitchValues() != null)
            {
                for (ASN1Encodable enc : def.getValidSwitchValues())
                {
                    script.add(new ASN1Enumerated(ASN1Integer.getInstance(enc).getValue()));
                }
            }
            else
            {
                for (Element e : def.getChildren())
                {
                    if (e.getBaseType() == OERDefinition.BaseType.EXTENSION)
                    {
                        continue;
                    }
                    script.add(new ASN1Enumerated(i++));
                }
            }
        }


        public boolean isFinished(int tick)
        {
            return cnt >= script.size();
        }


        public ASN1Encodable populate(int tick, ASN1Encodable[] priorValues)
        {
            if (cnt > script.size() - 1)
            {
                cnt = 0;
            }

            return script.get(cnt++);
        }
    }


    public class SeqOfPopulate
        implements Populate
    {

        private final Element def;
        private int cnt = 0;
        List<Populate> script = new ArrayList<Populate>();

        public SeqOfPopulate(Element def)
        {
            this.def = def;

            int l = 5;
            if (def.getLowerBound() != null)
            {
                l = def.getLowerBound().intValue();
            }
            if (def.getUpperBound() != null)
            {
                l = def.getUpperBound().intValue();
            }
            for (; l > 0; l--)
            {
                script.add(makePopulate(def.getFirstChid(), false));
            }
        }


        public boolean isFinished(int tick)
        {
            for (Populate p : script)
            {
                if (!p.isFinished(tick))
                {
                    return false;
                }
            }

            return cnt == 1;
        }


        public ASN1Encodable populate(int tick, ASN1Encodable[] priorValues)
        {
            if (cnt > 0)
            {
                cnt = 0;
            }

            ASN1Encodable[] values = new ASN1Encodable[script.size()];

            for (int t = 0; t < script.size(); t++)
            {
                values[t] = script.get(t).populate(tick, null);
            }
            cnt++;
            return new DERSequence(values);
        }
    }


    public static class TextStringPopulate
        implements Populate
    {
        private final Element def;
        List<ASN1Encodable> script = new ArrayList<ASN1Encodable>();
        private String part = "the cat sat on the mat";
        private StringBuffer expander = new StringBuffer();

        private int cnt = 0;

        public TextStringPopulate(Element def, OERDefinition.BaseType type)
        {
            this.def = def;

            if (def.isFixedLength())
            {
                int l = def.getUpperBound().intValue();
                if (l > 1024)
                {
                    l = 1024;
                }
                if (type == OERDefinition.BaseType.UTF8_STRING)
                {
                    script.add(new DERUTF8String(makeString(l)));
                }
                else if (type == OERDefinition.BaseType.IA5String)
                {
                    script.add(new DERIA5String(makeString(l)));
                }
                else
                {
                    throw new IllegalStateException("text type not supported in generator");
                }

                script.add(new DEROctetString(new byte[def.getUpperBound().intValue()]));
            }
            else
            {
                if (def.getUpperBound() != null)
                {
                    int l = def.getUpperBound().intValue();
                    if (l > 1024)
                    {
                        l = 1024;
                    }

                    if (type == OERDefinition.BaseType.UTF8_STRING)
                    {
                        script.add(new DERUTF8String(makeString(l)));
                    }
                    else if (type == OERDefinition.BaseType.IA5String)
                    {
                        script.add(new DERIA5String(makeString(l)));
                    }
                    else
                    {
                        throw new IllegalStateException("text type not supported in generator");
                    }
                }

                if (def.getLowerBound() != null)
                {
                    int l = def.getLowerBound().intValue();
                    if (l > 1024)
                    {
                        l = 1024;
                    }

                    if (type == OERDefinition.BaseType.UTF8_STRING)
                    {
                        script.add(new DERUTF8String(makeString(l)));
                    }
                    else if (type == OERDefinition.BaseType.IA5String)
                    {
                        script.add(new DERIA5String(makeString(l)));
                    }
                    else
                    {
                        throw new IllegalStateException("text type not supported in generator");
                    }
                }

                if (def.getLowerBound() == null && def.getUpperBound() == null)
                {
                    int l = 32;
                    if (type == OERDefinition.BaseType.UTF8_STRING)
                    {
                        script.add(new DERUTF8String(makeString(l)));
                    }
                    else if (type == OERDefinition.BaseType.IA5String)
                    {
                        script.add(new DERIA5String(makeString(l)));
                    }
                    else
                    {
                        throw new IllegalStateException("text type not supported in generator");
                    }
                }
            }

        }

        private String makeString(int len)
        {
            while (expander.length() < len)
            {
                expander.append(part);
            }
            return expander.substring(0, len);
        }


        public boolean isFinished(int tick)
        {
            return cnt == script.size();
        }


        public ASN1Encodable populate(int tick, ASN1Encodable[] priorValues)
        {
            if (cnt >= script.size())
            {
                cnt = 0;
            }
            return script.get(cnt++);
        }
    }


    public static class OctetStringPopulate
        implements Populate
    {
        private final Element def;
        List<ASN1Encodable> script = new ArrayList<ASN1Encodable>();
        int ctr = 0;

        public OctetStringPopulate(Element def)
        {
            this.def = def;

            if (def.isFixedLength())
            {
                script.add(new DEROctetString(new byte[def.getUpperBound().intValue()]));
            }
            else
            {
                if (def.getUpperBound() != null)
                {
                    script.add(new DEROctetString(new byte[def.getUpperBound().intValue()]));
                }

                if (def.getLowerBound() != null)
                {
                    script.add(new DEROctetString(new byte[def.getLowerBound().intValue()]));
                }

                if (def.getLowerBound() == null && def.getUpperBound() == null)
                {
                    script.add(new DEROctetString(new byte[32]));
                }
            }
        }


        public boolean isFinished(int tick)
        {
            return ctr == script.size();
        }


        public ASN1Encodable populate(int tick, ASN1Encodable[] priorValues)
        {
            if (ctr > script.size() - 1)
            {
                ctr = 0; // Lap back around again.
            }
            return script.get(ctr++);
        }
    }

    public static class BooleanPopulate
        implements Populate
    {

        private final Element def;
        private int ctr = 0;
        List<ASN1Encodable> script = new ArrayList<ASN1Encodable>();

        public BooleanPopulate(Element def)
        {
            this.def = def;

            script.add(ASN1Boolean.TRUE);
            script.add(ASN1Boolean.FALSE);

        }


        public boolean isFinished(int tick)
        {
            return ctr == script.size();
        }


        public ASN1Encodable populate(int tick, ASN1Encodable[] priorValues)
        {
            if (ctr > script.size() - 1)
            {
                ctr = 0;
            }

            return script.get(ctr++);
        }
    }


    public static class IntPopulate
        implements Populate
    {
        private final Element def;
        private int ctr = 0;
        List<ASN1Encodable> script = new ArrayList<ASN1Encodable>();

        public IntPopulate(Element def)
        {
            this.def = def;

            if (def.getValidSwitchValues() != null)
            {
                //
                // The unit has valid switch values so we need to use those.
                //


                for (ASN1Encodable e : def.getValidSwitchValues())
                {
                    script.add(ASN1Integer.getInstance(e));
                }
            }
            else
            {

                // Bounded
                if (def.getUpperBound() != null)
                {
                    script.add(new ASN1Integer(def.getUpperBound()));
                    // TODO add out of range.
                }

                if (def.getLowerBound() != null)
                {
                    script.add(new ASN1Integer(def.getLowerBound()));
                    // TODO add out of range
                }

                if (def.getLowerBound() == null && def.getUpperBound() == null)
                {
                    script.add(new ASN1Integer(10)); // Unbounded so pick a value.
                }
            }

        }


        public boolean isFinished(int tick)
        {
            return ctr == script.size();
        }


        public ASN1Encodable populate(int tick, ASN1Encodable[] priorValues)
        {
            if (ctr >= script.size())
            {
                ctr = 0;
            }

            return script.get(ctr++);
        }
    }


    public static class BitStringPopulate
        implements Populate
    {

        private final Element element;
        List<ASN1Encodable> script = new ArrayList<ASN1Encodable>();
        private int ctr = 0;

        public BitStringPopulate(Element element)
        {
            this.element = element;
            // So far there is only one reference to a bit string in the
            // templates we will just return that as empty.
            byte[] b = new byte[element.getUpperBound().intValue() / 8];
            script.add(new DERBitString(b));
        }


        public boolean isFinished(int tick)
        {
            return ctr == script.size();
        }


        public ASN1Encodable populate(int tick, ASN1Encodable[] priorValues)
        {
            if (ctr >= script.size())
            {
                ctr = 0;
            }

            return script.get(ctr++);
        }
    }


    public static class NullPopulate
        implements Populate
    {

        private final Element element;

        public NullPopulate(Element element)
        {
            this.element = element;
        }


        public boolean isFinished(int tick)
        {
            return true;
        }


        public ASN1Encodable populate(int tick, ASN1Encodable[] priorValues)
        {
            return DERNull.INSTANCE;
        }
    }


    public static class ExtensionPopulate
        implements Populate
    {

        private final Element element;

        private final DEROctetString value = new DEROctetString(Hex.decode("DEADBEEF0101"));

        public ExtensionPopulate(Element element)
        {
            this.element = element;
        }


        public boolean isFinished(int tick)
        {
            return true;
        }


        public ASN1Encodable populate(int tick, ASN1Encodable[] priorValues)
        {
            return value;
        }
    }


    public static class PopulateOptional
        implements Populate
    {

        private final Element element;
        private final Populate source;
        int ctr = 0;


        public PopulateOptional(Element element, Populate source)
        {
            this.element = element;
            this.source = source;
        }


        public boolean isFinished(int tick)
        {
            return source.isFinished(tick) && ctr == 2;
        }


        public ASN1Encodable populate(int tick, ASN1Encodable[] priorValues)
        {
            if (ctr == 2)
            {
                ctr = 0;
            }

            if (ctr == 0)
            {
                ctr++;
                if (element.getDefaultValue() != null)
                {
                    return element.getDefaultValue(); // Cannot return absent otherwise it gets filled in by the OERInputStream
                }
                return OEROptional.ABSENT;
            }
            else
            {
                ctr++;
                return source.populate(tick, null);
            }
        }
    }


    private static class ArrayOfAsn1
    {
        private final ASN1Encodable[] values;

        private ArrayOfAsn1(ASN1Encodable[] values)
        {
            this.values = new ASN1Encodable[values.length];
            for (int t = 0; t < values.length; t++)
            {
                this.values[t] = values[t];
            }
        }


        public boolean equals(Object o)
        {
            if (this == o)
            {
                return true;
            }
            if (o == null || getClass() != o.getClass())
            {
                return false;
            }

            ArrayOfAsn1 that = (ArrayOfAsn1)o;
            boolean z = Arrays.equals(values, that.values);
            // Probably incorrect - comparing Object[] arrays with Arrays.equals
            return z;
        }


        public int hashCode()
        {
            return Arrays.hashCode(values);
        }
    }


    public static class OERExpanderDepthException
        extends RuntimeException
    {
        private final Element element;
        private boolean outOfOptions = false;

        public OERExpanderDepthException(Element e, boolean outOfOptions)
        {
            super();
            this.element = e;
            this.outOfOptions = true;
        }

        public Element getElement()
        {
            return element;
        }

        public boolean isOutOfOptions()
        {
            return outOfOptions;
        }

        public void setOutOfOptions(boolean outOfOptions)
        {
            this.outOfOptions = outOfOptions;
        }
    }
}
