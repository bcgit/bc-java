package org.bouncycastle.kmip.wire.attribute;


import org.bouncycastle.kmip.wire.enumeration.KMIPUniqueIdentifierEnum;

public class KMIPUniqueIdentifier
{
    private String textValue;       // Unique identifier as a text string
    private KMIPUniqueIdentifierEnum enumValue; // Unique identifier as an enumeration
    private int intValue;       // Unique identifier as an integer
    private Identifier flag = Identifier.Unknown;

    private enum Identifier
    {
        Unknown, String, Enum, Integer
    }


    /**
     * Constructor for UniqueIdentifier using a String.
     *
     * @param textValue The text string identifier.
     */
    public KMIPUniqueIdentifier(String textValue)
    {
        this.textValue = textValue;
        flag = Identifier.String;
    }

    /**
     * Constructor for UniqueIdentifier using an Enumeration.
     *
     * @param enumValue The enumeration identifier.
     */
    public KMIPUniqueIdentifier(KMIPUniqueIdentifierEnum enumValue)
    {
        this.enumValue = enumValue;
        flag = Identifier.Enum;
    }

    /**
     * Constructor for UniqueIdentifier using an Integer.
     *
     * @param intValue The integer identifier.
     */
    public KMIPUniqueIdentifier(int intValue)
    {
        this.intValue = intValue;
        flag = Identifier.Integer;
    }

    /**
     * Get the text value of the unique identifier.
     *
     * @return The text value as a String.
     */
    public String getTextValue()
    {
        return textValue;
    }

    /**
     * Set the text value of the unique identifier.
     *
     * @param textValue The text value to set.
     */
    public void setTextValue(String textValue)
    {
        this.textValue = textValue;
    }

    /**
     * Get the enumeration value of the unique identifier.
     *
     * @return The enumeration value.
     */
    public KMIPUniqueIdentifierEnum getEnumValue()
    {
        return enumValue;
    }

    /**
     * Set the enumeration value of the unique identifier.
     *
     * @param enumValue The enumeration value to set.
     */
    public void setEnumValue(KMIPUniqueIdentifierEnum enumValue)
    {
        this.enumValue = enumValue;
    }

    /**
     * Get the integer value of the unique identifier.
     *
     * @return The integer value.
     */
    public int getIntValue()
    {
        return intValue;
    }

    /**
     * Set the integer value of the unique identifier.
     *
     * @param intValue The integer value to set.
     */
    public void setIntValue(int intValue)
    {
        this.intValue = intValue;
    }

    /**
     * Check which type of identifier is being used (Text, Enum, or int).
     *
     * @return The type of identifier.
     */
    public String getIdentifierType()
    {
        switch (flag)
        {
        case String:
            return "Text String";
        case Enum:
            return "Enumeration";
        case Integer:
            return "Integer";
        }
        return "Unknown";
    }

}

