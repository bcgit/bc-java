package org.bouncycastle.kmip.wire.attribute;

import org.bouncycastle.kmip.wire.enumeration.KMIPNameType;

/**
 * Represents the Name attribute used to identify and locate an object in the key management system.
 */
public class KMIPName
    implements KMIPAttribute
{

    private String nameValue;      // Human-readable name to identify the object
    private KMIPNameType nameType;     // Enum representing the type of name

    /**
     * Constructs a Name attribute with the given value and type.
     *
     * @param nameValue The value of the name (human-readable string).
     * @param nameType  The type of the name (an enumeration).
     */
    public KMIPName(String nameValue, KMIPNameType nameType)
    {
        if (nameValue == null || nameValue.isEmpty())
        {
            throw new IllegalArgumentException("Name value cannot be null or empty.");
        }
        if (nameType == null)
        {
            throw new IllegalArgumentException("Name type cannot be null.");
        }
        this.nameValue = nameValue;
        this.nameType = nameType;
    }

    // Getters and setters
    public String getNameValue()
    {
        return nameValue;
    }

    public void setNameValue(String nameValue)
    {
        if (nameValue == null || nameValue.isEmpty())
        {
            throw new IllegalArgumentException("Name value cannot be null or empty.");
        }
        this.nameValue = nameValue;
    }

    public KMIPNameType getNameType()
    {
        return nameType;
    }

    public void setNameType(KMIPNameType nameType)
    {
        if (nameType == null)
        {
            throw new IllegalArgumentException("Name type cannot be null.");
        }
        this.nameType = nameType;
    }
}

