package org.bouncycastle.kmip.wire.message;

import java.util.Map;

/**
 * The MessageExtension class represents an optional structure that can be appended
 * to any batch item for adding vendor-specific extensions in protocol messages.
 */
public class KMIPMessageExtension
{

    private String vendorIdentification;
    private boolean criticalityIndicator;
    private Map<String, Object> vendorExtension; // Map to hold vendor-specific extensions

    /**
     * Constructor to initialize MessageExtension with all required fields.
     *
     * @param vendorIdentification A text string that uniquely identifies the vendor.
     * @param criticalityIndicator Boolean indicating if the message is critical.
     * @param vendorExtension      A structure containing vendor-specific extensions.
     */
    public KMIPMessageExtension(String vendorIdentification, boolean criticalityIndicator, Map<String, Object> vendorExtension)
    {
        this.vendorIdentification = vendorIdentification;
        this.criticalityIndicator = criticalityIndicator;
        this.vendorExtension = vendorExtension;
    }

    /**
     * Gets the vendor identification.
     *
     * @return The vendor identification string.
     */
    public String getVendorIdentification()
    {
        return vendorIdentification;
    }

    /**
     * Gets the criticality indicator.
     *
     * @return The criticality indicator (True if critical, False otherwise).
     */
    public boolean isCriticalityIndicator()
    {
        return criticalityIndicator;
    }

    /**
     * Gets the vendor extension structure.
     *
     * @return The map containing vendor-specific extensions.
     */
    public Map<String, Object> getVendorExtension()
    {
        return vendorExtension;
    }

    /**
     * Sets the vendor identification.
     *
     * @param vendorIdentification The vendor identification string to set.
     */
    public void setVendorIdentification(String vendorIdentification)
    {
        this.vendorIdentification = vendorIdentification;
    }

    /**
     * Sets the criticality indicator.
     *
     * @param criticalityIndicator The criticality indicator to set (True for critical, False for non-critical).
     */
    public void setCriticalityIndicator(boolean criticalityIndicator)
    {
        this.criticalityIndicator = criticalityIndicator;
    }

    /**
     * Sets the vendor extension structure.
     *
     * @param vendorExtension A map of vendor-specific extensions to set.
     */
    public void setVendorExtension(Map<String, Object> vendorExtension)
    {
        this.vendorExtension = vendorExtension;
    }
}

