package org.bouncycastle.oer;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;

public class OERDefinition
{
    static final BigInteger[] uIntMax = new BigInteger[]{
        new BigInteger("256"),
        new BigInteger("65536"),
        new BigInteger("4294967296"),
        new BigInteger("18446744073709551616"),
    };

    static final BigInteger[][] sIntRange = new BigInteger[][]{
        new BigInteger[]{new BigInteger("-128"), new BigInteger("127")},
        new BigInteger[]{new BigInteger("-32768"), new BigInteger("32767")},
        new BigInteger[]{new BigInteger("-2147483648"), new BigInteger("2147483647")},
        new BigInteger[]{new BigInteger("-9223372036854775808"), new BigInteger("9223372036854775807")},
    };

    public static Builder integer()
    {
        return new Builder(BaseType.INT);
    }

    public static Builder integer(long val)
    {
        return new Builder(BaseType.INT).defaultValue(new ASN1Integer(val));
    }

    public static Builder bitString(long len)
    {
        return new Builder(BaseType.BIT_STRING).fixedSize(len);
    }

    public static Builder integer(BigInteger lower, BigInteger upper)
    {
        return new Builder(BaseType.INT).range(lower, upper);
    }

    public static Builder integer(long lower, long upper)
    {
        return new Builder(BaseType.INT).range(BigInteger.valueOf(lower), BigInteger.valueOf(upper));
    }

    public static Builder integer(long lower, long upper, ASN1Encodable defaultValue)
    {
        return new Builder(BaseType.INT).range(lower, upper, defaultValue);
    }

    public static Builder nullValue()
    {
        return new Builder(BaseType.NULL);
    }

    public static Builder seq()
    {
        return new Builder(BaseType.SEQ);
    }

    public static Builder seq(Object... items)
    {
        return new Builder(BaseType.SEQ).items(items);
    }

    public static Builder aSwitch(Switch aSwitch)
    {
        return new Builder(BaseType.Switch).decodeSwitch(aSwitch);
    }

    public static Builder enumItem(String label)
    {
        return new Builder(BaseType.ENUM_ITEM).label(label);
    }

    public static Builder enumItem(String label, BigInteger value)
    {
        return new Builder(BaseType.ENUM_ITEM).enumValue(value).label(label);
    }

    public static Builder enumeration(Object... items)
    {
        return new Builder(BaseType.ENUM).items(items);
    }

    public static Builder choice(Object... items)
    {
        return new Builder(BaseType.CHOICE).items(items);
    }

    public static Builder placeholder()
    {
        return new Builder(null);
    }

    public static Builder seqof(Object... items)
    {
        return new Builder(BaseType.SEQ_OF).items(items);
    }

    public static Builder octets()
    {
        return new Builder(BaseType.OCTET_STRING).unbounded();
    }

    public static Builder octets(int size)
    {
        return new Builder(BaseType.OCTET_STRING).fixedSize(size);
    }

    public static Builder octets(int lowerBound, int upperBound)
    {
        return new Builder(BaseType.OCTET_STRING).range(BigInteger.valueOf(lowerBound), BigInteger.valueOf(upperBound));
    }

    public static Builder ia5String()
    {
        return new Builder(BaseType.IA5String);
    }

    public static Builder utf8String()
    {
        return new Builder(BaseType.UTF8_STRING);
    }

    public static Builder utf8String(int size)
    {
        return new Builder(BaseType.UTF8_STRING).rangeToMAXFrom(size);
    }

    public static Builder utf8String(int lowerBound, int upperBound)
    {
        return new Builder(BaseType.UTF8_STRING).range(BigInteger.valueOf(lowerBound), BigInteger.valueOf(upperBound));
    }

    public static Builder opaque()
    {
        return new Builder(BaseType.OCTET_STRING).unbounded();
    }

    public static List<Object> optional(Object... items)
    {
        return new OptionalList(Arrays.asList(items));
    }

    public static Builder extension()
    {
        return new Builder(BaseType.EXTENSION).label("extension");
    }

    public static Builder deferred(ElementSupplier elementSupplier)
    {
        return new OERDefinition.Builder(BaseType.Supplier).elementSupplier(elementSupplier);
    }


    public enum BaseType
    {
        SEQ, SEQ_OF, CHOICE, ENUM, INT, OCTET_STRING,
        UTF8_STRING, BIT_STRING, NULL, EXTENSION, ENUM_ITEM, BOOLEAN, IS0646String, PrintableString, NumericString,
        BMPString, UniversalString, IA5String, VisibleString, Switch, Supplier
    }

    public interface ItemProvider
    {
        Builder exitingChild(int index, Builder existingChild);
    }

    public interface ElementSupplier
    {
        Element build();
    }


    public static class Builder
    {
        protected final BaseType baseType;
        protected ArrayList<Builder> children = new ArrayList<Builder>();
        protected boolean explicit = true;
        protected String label;
        protected BigInteger upperBound;
        protected BigInteger lowerBound;
        protected BigInteger enumValue;
        protected ASN1Encodable defaultValue;
        protected Builder placeholderValue;
        protected Boolean inScope;
        protected Switch aSwitch;
        protected ArrayList<ASN1Encodable> validSwitchValues = new ArrayList<>();
        protected ElementSupplier elementSupplier;
        protected boolean mayRecurse;

        public Builder(BaseType baseType)
        {
            this.baseType = baseType;
        }

        private final ItemProvider defaultItemProvider = new ItemProvider()
        {
            public Builder exitingChild(int index, Builder existingChild)
            {
                return existingChild.copy(defaultItemProvider);
            }
        };

        private Builder copy(ItemProvider provider)
        {
            Builder b = new Builder(baseType);
            int t = 0;
            for (Iterator it = children.iterator(); it.hasNext(); )
            {
                Builder child = (Builder)it.next();
                b.children.add(provider.exitingChild(t++, child));
            }
            b.explicit = explicit;
            b.label = label;
            b.upperBound = upperBound;
            b.lowerBound = lowerBound;
            b.defaultValue = defaultValue;
            b.enumValue = enumValue;
            b.inScope = inScope;
            b.aSwitch = aSwitch;
            b.validSwitchValues = new ArrayList<>(validSwitchValues);
            b.elementSupplier = elementSupplier;
            b.mayRecurse = mayRecurse;
            return b;
        }

        public Builder copy()
        {
            return copy(defaultItemProvider);
        }

        public Builder elementSupplier(ElementSupplier elementSupplier)
        {
            Builder b = this.copy();
            b.elementSupplier = elementSupplier;
            return b;
        }

        public Builder validSwitchValue(ASN1Encodable... values)
        {
            Builder b = this.copy();
            b.validSwitchValues.addAll(Arrays.asList(values));
            return b;
        }

        public Builder inScope(boolean scope)
        {
            Builder b = this.copy();
            b.inScope = scope;
            return b;
        }

        public Builder limitScopeTo(String... label)
        {
            Builder b = this.copy();
            HashSet<String> labels = new HashSet<String>();
            labels.addAll(Arrays.asList(label));

            ArrayList<Builder> scopeLimited = new ArrayList<Builder>();

            for (Iterator it = children.iterator(); it.hasNext(); )
            {
                Builder child = (Builder)it.next();
                scopeLimited.add(child.copy().inScope(labels.contains(child.label)));
            }
            b.children = scopeLimited;

            return b;
        }


        public Builder unbounded()
        {
            Builder b = this.copy();
            b.lowerBound = null;
            b.upperBound = null;
            return b;
        }

        public Builder decodeSwitch(Switch aSwitch)
        {
            Builder cpy = copy();
            cpy.aSwitch = aSwitch;
            return cpy;
        }

        public Builder labelPrefix(String prefix)
        {
            Builder cpy = copy();
            cpy.label = prefix + " " + label;
            return cpy;
        }

        public Builder explicit(boolean explicit)
        {
            Builder b = this.copy();
            b.explicit = explicit;
            return b;
        }

        public Builder defaultValue(ASN1Encodable defaultValue)
        {
            Builder b = this.copy();
            b.defaultValue = defaultValue;
            return b;
        }

        protected Builder wrap(boolean explicit, Object item)
        {
            if (item instanceof Builder)
            {
                return ((Builder)item).explicit(explicit);
            }
            else if (item instanceof BaseType)
            {
                return new Builder((BaseType)item).explicit(explicit);
            }

            throw new IllegalStateException("Unable to wrap item in builder");
        }

        public Builder items(Object... items)
        {
            final Builder b = this.copy();

            for (int i = 0; i != items.length; i++)
            {
                Object item = items[i];
                if (item instanceof OptionalList)
                {
                    for (Iterator it = ((List)item).iterator(); it.hasNext(); )
                    {
                        b.children.add(wrap(false, it.next()));
                    }
                }
                else
                {

                    if (item.getClass().isArray())
                    {
                        items((Object[])item);
                    }
                    else
                    {
                        b.children.add(wrap(true, item));
                    }
                }
            }
            return b;
        }

        public Builder label(String label)
        {
            Builder newBuilder = this.copy();

            if (label != null)
            {
                newBuilder.label = label;
            }

            newBuilder.explicit = explicit;
            return newBuilder;
        }

        public Builder mayRecurse(boolean val)
        {
            Builder b = this.copy();
            b.mayRecurse = val;
            return b;
        }

        public Element build()
        {
            List<Element> children = new ArrayList<Element>();
            boolean hasExtensions = false;

            if (baseType == BaseType.ENUM)
            {
                int ordinal = 0;
                HashSet<BigInteger> dupCheck = new HashSet<BigInteger>();
                for (int t = 0; t < this.children.size(); t++)
                {
                    Builder b = this.children.get(t);
                    if (b.enumValue == null)
                    {
                        b.enumValue = BigInteger.valueOf(ordinal);
                        ordinal++;
                    }

                    if (!dupCheck.contains(b.enumValue))
                    {
                        dupCheck.add(b.enumValue);
                    }
                    else
                    {
                        throw new IllegalStateException("duplicate enum value at index " + t);
                    }
                }
            }

            for (Iterator it = this.children.iterator(); it.hasNext(); )
            {
                Builder b = (Builder)it.next();

                if (!hasExtensions && b.baseType == BaseType.EXTENSION)
                {
                    hasExtensions = true;
                    if (b.children.isEmpty())
                    {
                        //
                        // There was an extension point but it was empty.
                        // So drop it from the list of children.
                        //
                        if (this.baseType != BaseType.CHOICE && this.baseType != BaseType.ENUM)
                        {
                            continue;
                        }
                    }
                }

                children.add(b.build());
            }


            return new Element(
                baseType,
                children,
                defaultValue == null && explicit,
                label,
                lowerBound,
                upperBound,
                hasExtensions,
                enumValue, defaultValue, aSwitch, validSwitchValues.isEmpty() ? null : validSwitchValues, elementSupplier, mayRecurse);

        }

        public Builder range(BigInteger lower, BigInteger upper)
        {
            Builder newBuilder = this.copy();
            newBuilder.lowerBound = lower;
            newBuilder.upperBound = upper;
            return newBuilder;
        }

        public Builder rangeToMAXFrom(long from)
        {
            Builder b = this.copy();
            b.lowerBound = BigInteger.valueOf(from);
            b.upperBound = null;
            return b;
        }

        public Builder rangeZeroTo(long max)
        {
            Builder b = this.copy();
            b.upperBound = BigInteger.valueOf(max);
            b.lowerBound = BigInteger.ZERO;
            return b;
        }

        public Builder fixedSize(long size)
        {
            Builder b = this.copy();
            b.upperBound = BigInteger.valueOf(size);
            b.lowerBound = BigInteger.valueOf(size);
            return b;
        }

        public Builder range(long lower, long upper, ASN1Encodable defaultIntValue)
        {
            Builder b = this.copy();
            b.lowerBound = BigInteger.valueOf(lower);
            b.upperBound = BigInteger.valueOf(upper);
            b.defaultValue = defaultIntValue;
            return b;
        }

        public Builder enumValue(BigInteger value)
        {
            Builder b = this.copy();
            this.enumValue = value;
            return b;
        }

        public Builder replaceChild(final int index, final Builder newItem)
        {
            return this.copy(new ItemProvider()
            {
                public Builder exitingChild(int _index, Builder existingChild)
                {
                    return index == _index ? newItem : existingChild;
                }
            });
        }


    }

    public static class MutableBuilder
        extends Builder
    {

        private boolean frozen = false;

        public MutableBuilder(BaseType baseType)
        {
            super(baseType);
        }

        public MutableBuilder label(String label)
        {
            this.label = label;
            return this;
        }

        public MutableBuilder addItemsAndFreeze(Builder... items)
        {
            if (frozen)
            {
                throw new IllegalStateException("build cannot be modified and must be copied only");
            }

            for (int i = 0; i != items.length; i++)
            {
                Object item = items[i];
                if (item instanceof OptionalList)
                {
                    for (Iterator it = ((List)item).iterator(); it.hasNext(); )
                    {
                        super.children.add(wrap(false, it.next()));
                    }
                }
                else
                {

                    if (item.getClass().isArray())
                    {
                        for (Object o : (Object[])item)
                        {
                            super.children.add(wrap(true, o));
                        }
                    }
                    else
                    {
                        super.children.add(wrap(true, item));
                    }
                }
            }

            frozen = true;
            return this;
        }
    }

    private static class OptionalList
        extends ArrayList<Object>
    {

        public OptionalList(List<Object> asList)
        {
            addAll(asList);
        }
    }

}
