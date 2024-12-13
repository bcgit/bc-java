package org.bouncycastle.kmip.wire.message;

/**
 * This class represents the protocol version structure, containing both
 * the major and minor version numbers. It ensures the compatibility
 * of the protocol between communicating parties.
 */
public class KMIPProtocolVersion
{

    private final int majorVersion;
    private final int minorVersion;

    /**
     * Constructor for KMIPProtocolVersion.
     *
     * @param majorVersion The major version number of the protocol.
     * @param minorVersion The minor version number of the protocol.
     */
    public KMIPProtocolVersion(int majorVersion, int minorVersion)
    {
        this.majorVersion = majorVersion;
        this.minorVersion = minorVersion;
    }

    /**
     * Retrieves the major version of the protocol.
     *
     * @return the major version as an integer.
     */
    public int getMajorVersion()
    {
        return majorVersion;
    }

    /**
     * Retrieves the minor version of the protocol.
     *
     * @return the minor version as an integer.
     */
    public int getMinorVersion()
    {
        return minorVersion;
    }

    /**
     * Compares the current protocol version to another KMIPProtocolVersion instance.
     *
     * @param other the other ProtocolVersion to compare with.
     * @return true if the major versions match and the current minor version is greater
     * than or equal to the other version's minor version.
     */
    public boolean isCompatibleWith(KMIPProtocolVersion other)
    {
        return this.majorVersion == other.majorVersion && this.minorVersion >= other.minorVersion;
    }

    @Override
    public String toString()
    {
        return "ProtocolVersion " + majorVersion + "." + minorVersion;
    }
}

