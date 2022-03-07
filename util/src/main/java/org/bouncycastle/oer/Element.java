package org.bouncycastle.oer;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;

/**
 * OER Element is the result of building the OER definition.
 */
public class Element
{
    private final OERDefinition.BaseType baseType;
    private final List<Element> children;
    private final boolean explicit;
    private final String label;
    private final BigInteger lowerBound;
    private final BigInteger upperBound;
    private final boolean extensionsInDefinition;
    private final BigInteger enumValue;
    private final ASN1Encodable defaultValue;
    private final Switch aSwitch;
    private final boolean defaultValuesInChildren;
    private List<Element> optionalChildrenInOrder;
    private List<ASN1Encodable> validSwitchValues;
    private final ElementSupplier elementSupplier;
    private final boolean mayRecurse;
    private final String typeName;
    private final Map<String, ElementSupplier> supplierMap;
    private Element parent;
    private final int optionals;
    /**
     * This element is in the extension area of another element.
     */
    private final int block;

    public Element(
        OERDefinition.BaseType baseType,
        List<Element> children,
        boolean explicit,
        String label,
        BigInteger lowerBound,
        BigInteger upperBound,
        boolean extensionsInDefinition,
        BigInteger enumValue, ASN1Encodable defaultValue, Switch aSwitch,
        List<ASN1Encodable> switchValues,
        ElementSupplier elementSupplier,
        boolean mayRecurse, String typeName, Map<String, ElementSupplier> supplierMap, int block, int optionals, boolean defaultValuesInChildren)
    {
        this.baseType = baseType;
        this.children = children;
        this.explicit = explicit;
        this.label = label;
        this.lowerBound = lowerBound;
        this.upperBound = upperBound;
        this.extensionsInDefinition = extensionsInDefinition;
        this.enumValue = enumValue;
        this.defaultValue = defaultValue;
        this.aSwitch = aSwitch;
        this.validSwitchValues = switchValues != null ? Collections.unmodifiableList(switchValues) : null;
        this.elementSupplier = elementSupplier;
        this.mayRecurse = mayRecurse;
        this.typeName = typeName;
        this.block = block;
        this.optionals = optionals;
        this.defaultValuesInChildren = defaultValuesInChildren;
        if (supplierMap == null)
        {
            this.supplierMap = Collections.emptyMap();
        }
        else
        {
            this.supplierMap = supplierMap;
        }

        for (Element e : children)
        {
            e.parent = this;
        }
    }

    public Element(Element element, Element parent)
    {
        this.baseType = element.baseType;
        this.children = new ArrayList<Element>(element.children);
        this.explicit = element.explicit;
        this.label = element.label;
        this.lowerBound = element.lowerBound;
        this.upperBound = element.upperBound;
        this.extensionsInDefinition = element.extensionsInDefinition;
        this.enumValue = element.enumValue;
        this.defaultValue = element.defaultValue;
        this.aSwitch = element.aSwitch;
        this.validSwitchValues = element.validSwitchValues;
        this.elementSupplier = element.elementSupplier;
        this.mayRecurse = element.mayRecurse;
        this.typeName = element.typeName;
        this.supplierMap = element.supplierMap;
        this.parent = parent;
        this.block = element.block;
        this.optionals = element.optionals;
        this.defaultValuesInChildren = element.defaultValuesInChildren;
        for (Element e : this.children)
        {
            e.parent = this;
        }
    }


    /**
     * Expands the definition if the element holds an element supplier.
     *
     * @param e      The element.
     * @param parent
     * @return the expanded definition or the passed in element if it has no supplier.
     */
    public static Element expandDeferredDefinition(Element e, Element parent)
    {
        if (e.elementSupplier != null)
        {
            e = e.elementSupplier.build();
            if (e.getParent() != parent)
            {
                e = new Element(e, parent);
            }
        }
        return e;
    }

    public String rangeExpression()
    {
        return "(" + (getLowerBound() != null ? getLowerBound().toString() : "MIN") + " ... "
            + (getUpperBound() != null ? getUpperBound().toString() : "MAX") + ")";
    }

    public String appendLabel(String s)
    {
        return "[" + (getLabel() == null ? "" : getLabel()) + (isExplicit() ? " (E)" : "") + "] " + s;
    }

    public List<Element> optionalOrDefaultChildrenInOrder()
    {
        synchronized (this)
        {
            // do it once, these definitions can be shared about.
            if (getOptionalChildrenInOrder() == null)
            {
                ArrayList<Element> optList = new ArrayList<Element>();
                for (Iterator it = getChildren().iterator(); it.hasNext(); )
                {
                    Element e = (Element)it.next();
                    if (!e.isExplicit() || e.getDefaultValue() != null)
                    {
                        optList.add(e);
                    }
                }
                optionalChildrenInOrder = Collections.unmodifiableList(optList);
            }
            return getOptionalChildrenInOrder();
        }
    }

    public boolean isUnbounded()
    {
        return getUpperBound() == null && getLowerBound() == null;
    }

    public boolean isLowerRangeZero()
    {
        return BigInteger.ZERO.equals(getLowerBound());
    }


    /**
     * Return true in cases where the range is all positive (0 .. 10)
     *
     * @return true if condition met.
     */
    public boolean isUnsignedWithRange()
    {
        return isLowerRangeZero() && (getUpperBound() != null && BigInteger.ZERO.compareTo(getUpperBound()) < 0);
    }


    // True for cases where there is no lower bound or lower bound is less than zero.
    public boolean canBeNegative()
    {
        return getLowerBound() != null && BigInteger.ZERO.compareTo(getLowerBound()) > 0;
    }


    /**
     * Determine the number of integer bytes for a range, ints, signed or unsigned that can fit into 1 to 8 octets
     * use a fixed with encoding.
     * Returns a negative number if the value is signed and the absolute value is the number of bytes.
     */
    public int intBytesForRange()
    {
        if (getLowerBound() != null && getUpperBound() != null)
        {
            if (BigInteger.ZERO.equals(getLowerBound()))
            {
                //
                // Positive range.
                //

                for (int i = 0, j = 1; i < OERDefinition.uIntMax.length; i++, j *= 2)
                {
                    if (getUpperBound().compareTo(OERDefinition.uIntMax[i]) < 0)
                    {
                        return j;
                    }
                }
            }
            else
            {
                for (int i = 0, j = 1; i < OERDefinition.sIntRange.length; i++, j *= 2)
                {
                    if (getLowerBound().compareTo(OERDefinition.sIntRange[i][0]) >= 0 && getUpperBound().compareTo(OERDefinition.sIntRange[i][1]) < 0)
                    {
                        return -j;
                    }
                }
            }
        }
        return 0;
    }

    public boolean hasPopulatedExtension()
    {
        return this.extensionsInDefinition;
    }

    public boolean hasDefaultChildren()
    {
        return defaultValuesInChildren;
    }

    public ASN1Encodable getDefaultValue()
    {
        return defaultValue;
    }


    public Element getFirstChid()
    {
        return getChildren().get(0);
    }

    public boolean isFixedLength()
    {
        return getLowerBound() != null && (getLowerBound().equals(getUpperBound()));
    }

    @Override
    public String toString()
    {
        return "[" + typeName + " " + baseType.name() + " '" + getLabel() + "']";
    }

    public OERDefinition.BaseType getBaseType()
    {
        return baseType;
    }


    public List<Element> getChildren()
    {
        return children;
    }

    public boolean isExplicit()
    {
        return explicit;
    }

    public String getLabel()
    {
        return label;
    }

    public BigInteger getLowerBound()
    {
        return lowerBound;
    }

    public BigInteger getUpperBound()
    {
        return upperBound;
    }

    public boolean isExtensionsInDefinition()
    {
        return extensionsInDefinition;
    }

    public BigInteger getEnumValue()
    {
        return enumValue;
    }

    public Switch getaSwitch()
    {
        return aSwitch;
    }

    public List<Element> getOptionalChildrenInOrder()
    {
        return optionalChildrenInOrder;
    }

    public List<ASN1Encodable> getValidSwitchValues()
    {
        return validSwitchValues;
    }

    public ElementSupplier getElementSupplier()
    {
        return elementSupplier;
    }

    public boolean isMayRecurse()
    {
        return mayRecurse;
    }

    public String getTypeName()
    {
        return typeName;
    }

    public int getOptionals()
    {
        return optionals;
    }

    public int getBlock()
    {
        return block;
    }

    public String getDerivedTypeName()
    {

        if (typeName != null)
        {
            return typeName;
        }

        return baseType.name();

    }

    public ElementSupplier resolveSupplier()
    {
        if (supplierMap.containsKey(label))
        {
            return supplierMap.get(label);
        }

        if (parent != null)
        {
            return parent.resolveSupplier(label);
        }

        throw new IllegalStateException("unable to resolve: " + label);
    }

    protected ElementSupplier resolveSupplier(String name)
    {
        name = label + "." + name;
        if (supplierMap.containsKey(name))
        {
            return supplierMap.get(name);
        }

        if (parent != null)
        {
            return parent.resolveSupplier(name);
        }

        throw new IllegalStateException("unable to resolve: " + name);

    }

    public Element getParent()
    {
        return parent;
    }

    @Override
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

        Element element = (Element)o;

        if (explicit != element.explicit)
        {
            return false;
        }
        if (extensionsInDefinition != element.extensionsInDefinition)
        {
            return false;
        }
        if (defaultValuesInChildren != element.defaultValuesInChildren)
        {
            return false;
        }
        if (mayRecurse != element.mayRecurse)
        {
            return false;
        }
        if (optionals != element.optionals)
        {
            return false;
        }
        if (block != element.block)
        {
            return false;
        }
        if (baseType != element.baseType)
        {
            return false;
        }
        if (children != null ? !children.equals(element.children) : element.children != null)
        {
            return false;
        }
        if (label != null ? !label.equals(element.label) : element.label != null)
        {
            return false;
        }
        if (lowerBound != null ? !lowerBound.equals(element.lowerBound) : element.lowerBound != null)
        {
            return false;
        }
        if (upperBound != null ? !upperBound.equals(element.upperBound) : element.upperBound != null)
        {
            return false;
        }
        if (enumValue != null ? !enumValue.equals(element.enumValue) : element.enumValue != null)
        {
            return false;
        }
        if (defaultValue != null ? !defaultValue.equals(element.defaultValue) : element.defaultValue != null)
        {
            return false;
        }
        if (aSwitch != null ? !aSwitch.equals(element.aSwitch) : element.aSwitch != null)
        {
            return false;
        }
        if (optionalChildrenInOrder != null ? !optionalChildrenInOrder.equals(element.optionalChildrenInOrder) : element.optionalChildrenInOrder != null)
        {
            return false;
        }
        if (validSwitchValues != null ? !validSwitchValues.equals(element.validSwitchValues) : element.validSwitchValues != null)
        {
            return false;
        }
        if (elementSupplier != null ? !elementSupplier.equals(element.elementSupplier) : element.elementSupplier != null)
        {
            return false;
        }
        if (typeName != null ? !typeName.equals(element.typeName) : element.typeName != null)
        {
            return false;
        }
        return supplierMap != null ? !supplierMap.equals(element.supplierMap) : element.supplierMap != null;

//        {
//            return false;
//        }
//        return parent != null ? parent.equals(element.parent) : element.parent == null;
    }

    @Override
    public int hashCode()
    {
        int result = baseType != null ? baseType.hashCode() : 0;
        result = 31 * result + (children != null ? children.hashCode() : 0);
        result = 31 * result + (explicit ? 1 : 0);
        result = 31 * result + (label != null ? label.hashCode() : 0);
        result = 31 * result + (lowerBound != null ? lowerBound.hashCode() : 0);
        result = 31 * result + (upperBound != null ? upperBound.hashCode() : 0);
        result = 31 * result + (extensionsInDefinition ? 1 : 0);
        result = 31 * result + (enumValue != null ? enumValue.hashCode() : 0);
        result = 31 * result + (defaultValue != null ? defaultValue.hashCode() : 0);
        result = 31 * result + (aSwitch != null ? aSwitch.hashCode() : 0);
        result = 31 * result + (defaultValuesInChildren ? 1 : 0);
        result = 31 * result + (optionalChildrenInOrder != null ? optionalChildrenInOrder.hashCode() : 0);
        result = 31 * result + (validSwitchValues != null ? validSwitchValues.hashCode() : 0);
        result = 31 * result + (elementSupplier != null ? elementSupplier.hashCode() : 0);
        result = 31 * result + (mayRecurse ? 1 : 0);
        result = 31 * result + (typeName != null ? typeName.hashCode() : 0);
        result = 31 * result + (supplierMap != null ? supplierMap.hashCode() : 0);
        // Causes recursion.
        //   result = 31 * result + (parent != this ?  (parent != null ? parent.hashCode() : 0):0);
        result = 31 * result + optionals;
        result = 31 * result + block;
        return result;
    }
}
