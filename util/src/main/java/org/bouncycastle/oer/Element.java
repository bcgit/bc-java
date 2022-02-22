package org.bouncycastle.oer;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

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
    private List<Element> optionalChildrenInOrder;
    private List<ASN1Encodable> validSwitchValues;
    private final OERDefinition.ElementSupplier elementSupplier;
    private final boolean mayRecurse;
    private final String typeName;

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
        OERDefinition.ElementSupplier elementSupplier,
        boolean mayRecurse, String typeName)
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
    }

    /**
     * Expands the definition if the element holds an element supplier.
     *
     * @param e The element.
     * @return the expanded definition or the passed in element if it has no supplier.
     */
    public static Element expandDeferredDefinition(Element e)
    {
        if (e.elementSupplier != null)
        {
            return e.elementSupplier.build();
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
        for (Iterator it = getChildren().iterator(); it.hasNext(); )
        {
            Element child = (Element)it.next();
            if (child.getBaseType() == OERDefinition.BaseType.EXTENSION)
            {
                return true;
            }
        }
        return false;
    }

    public boolean hasDefaultChildren()
    {
        for (Iterator it = getChildren().iterator(); it.hasNext(); )
        {
            Element child = (Element)it.next();
            if (child.getDefaultValue() != null)
            {
                return true;
            }
        }
        return false;
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
        return "Element{" +
            "label='" + getLabel() + '\'' +
            '}';
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

    public OERDefinition.ElementSupplier getElementSupplier()
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

    public String getDerivedTypeName()
    {

        if (typeName != null)
        {
            return typeName;
        }

        return baseType.name();

    }

}
