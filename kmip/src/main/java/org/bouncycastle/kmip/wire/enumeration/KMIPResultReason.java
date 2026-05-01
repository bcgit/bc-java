package org.bouncycastle.kmip.wire.enumeration;

/**
 * This field indicates a reason for failure or a modifier for a partially successful operation and SHALL be
 * present in responses that return a Result Status of Failure. In such a case, the Result Reason SHALL be
 * set as specified. It SHALL NOT be present in any response that returns a Result Status of Success.
 */
public enum KMIPResultReason
    implements KMIPEnumeration
{

    /**
     * No object with the specified Unique Identifier exists.
     */
    ItemNotFound(0x00000001),

    /**
     * Maximum Response Size has been exceeded.
     */
    ResponseTooLarge(0x00000002),

    /**
     * The authentication information in the request could not be validated, or was not found.
     */
    AuthenticationNotSuccessful(0x00000003),

    /**
     * The request message was not syntactically understood by the server.
     */
    InvalidMessage(0x00000004),

    /**
     * The operation requested by the request message is not supported by the server.
     */
    OperationNotSupported(0x00000005),

    /**
     * The operation required additional information in the request, which was not present.
     */
    MissingData(0x00000006),

    /**
     * The request is syntactically valid but some data in the request (other than an attribute value) has an invalid value.
     */
    InvalidField(0x00000007),

    /**
     * The operation is supported, but a specific feature specified in the request is not supported.
     */
    FeatureNotSupported(0x00000008),

    /**
     * The asynchronous operation was canceled by the Cancel operation before it completed successfully.
     */
    OperationCanceledByRequester(0x00000009),

    /**
     * The operation failed due to a cryptographic error.
     */
    CryptographicFailure(0x0000000A),

    /**
     * Client is not allowed to perform the specified operation.
     */
    PermissionDenied(0x0000000C),

    /**
     * The object SHALL be recovered from the archive before performing the operation.
     */
    ObjectArchived(0x0000000D),

    /**
     * The particular Application Namespace is not
     * supported, and the server was not able to generate
     * the Application Data field of an Application Specific
     * Information attribute if the field was omitted from
     * the client request
     */
    ApplicationNamespaceNotSupported(0x0000000F),

    /**
     * The object exists, but the server is unable to provide it in the desired Key Format Type.
     */
    KeyFormatTypeNotSupported(0x00000010),

    /**
     * The object exists, but the server is unable to provide it in the desired Key Compression Type.
     */
    KeyCompressionTypeNotSupported(0x00000011),

    /**
     * The Encoding Option is not supported as specified by the Encoding Option Enumeration.
     */
    EncodingOptionError(0x00000012),

    /**
     * A meta-data only object. The key value is not present on the server.
     */
    KeyValueNotPresent(0x00000013),

    /**
     * Operation requires attestation data which was not
     * provided by the client, and the client has set the
     * Attestation Capable indicator to True
     */
    AttestationRequired(0x00000014),

    /**
     * Operation requires attestation data and the
     * attestation data provided by the client does not
     * validate
     */
    AttestationFailed(0x00000015),

    /**
     * Sensitive keys may not be retrieved unwrapped.
     */
    Sensitive(0x00000016),

    /**
     * Object is not extractable.
     */
    NotExtractable(0x00000017),

    /**
     * for operations such as Import that require that no object with a specific unique identifier exists on a server
     */
    ObjectAlreadyExists(0x00000018),

    /**
     * The ticket provided was invalid.
     */
    InvalidTicket(0x00000019),

    /**
     * The usage limits or request count has been exceeded.
     */
    UsageLimitExceeded(0x0000001A),

    /**
     * The operation produced a number that is too large or too small to be stored in the specified data type.
     */
    NumericRange(0x0000001B),

    /**
     * A data type was invalid for the requested operation.
     */
    InvalidDataType(0x0000001C),

    /**
     * Attempt to set a Read Only Attribute.
     */
    ReadOnlyAttribute(0x0000001D),

    /**
     * Attempt to Set or Adjust an attribute that has multiple values
     */
    MultiValuedAttribute(0x0000001E),

    /**
     * Attribute is valid in the specification but unsupported by the server.
     */
    UnsupportedAttribute(0x0000001F),

    /**
     * A referenced attribute was found, but the specific instance was not found.
     */
    AttributeInstanceNotFound(0x00000020),

    /**
     * A referenced attribute was not found at all on an object
     */
    AttributeNotFound(0x00000021),

    /**
     * Attempt to set a Read Only Attribute.
     */
    AttributeReadOnly(0x00000022),

    /**
     * Attempt to provide multiple values for a single instance attribute.
     */
    AttributeSingleValued(0x00000023),

    /**
     * The cryptographic parameters provided are invalid.
     */
    BadCryptographicParameters(0x00000024),

    /**
     * Key Format Type is PKCS#12, but missing or
     * multiple PKCS#12 Password Links, or not Secret
     * Data, or not Active
     */
    BadPassword(0x00000025),

    /**
     * The low level TTLV, XML, JSON etc. was badly
     * formed and not understood by the server.TTLV
     * connections should be closed as future requests
     * might not be correctly separated
     */
    CodecError(0x00000026),

    /**
     * Check cannot be performed on this object type.
     */
    IllegalObjectType(0x00000028),

    /**
     * The cryptographic algorithm or other parameters are not valid for the requested operation.
     */
    IncompatibleCryptographicUsageMask(0x00000029),

    /**
     * The server encountered an internal error and could not process the request at this time.
     */
    InternalServerError(0x0000002A),

    /**
     * No outstanding operation with the specified Asynchronous Correlation Value exists.
     */
    InvalidAsynchronousCorrelationValue(0x0000002B),

    /**
     * An attribute is invalid for this object or operation.
     */
    InvalidAttribute(0x0000002C),

    /**
     * The value supplied for an attribute is invalid.
     */
    InvalidAttributeValue(0x0000002D),

    /**
     * For streaming cryptographic operations, the correlation value is invalid.
     */
    InvalidCorrelationValue(0x0000002E),

    /**
     * Invalid Certificate Signing Request (CSR).
     */
    InvalidCSR(0x0000002F),

    /**
     * Specified object is not valid for the requested operation.
     */
    InvalidObjectType(0x00000030),

    /**
     * Key Wrap Type Type is not supported by the server
     */
    KeyWrapTypeNotSupported(0x00000032),

    /**
     * Missing IV when required for crypto operation
     */
    MissingInitializationVector(0x00000034),

    /**
     * Trying to perform an operation that requests the server to break the constraint on Name attribute being unique
     */
    NonUniqueNameAttribute(0x00000035),

    /**
     * Object exists, but has already been destroyed.
     */
    ObjectDestroyed(0x00000036),

    /**
     * A requested managed object was not found or did not exist.
     */
    ObjectNotFound(0x00000037),

    /**
     * Server limit has been exceeded, such as database size limit.
     */
    ServerLimitExceeded(0x0000003A),

    /**
     * An enumerated value is not known by the server.
     */
    UnknownEnumeration(0x0000003B),

    /**
     * The server does not support the supplied Message Extension.
     */
    UnknownMessageExtension(0x0000003C),

    /**
     * A tag is not known by the server.
     */
    UnknownTag(0x0000003D),

    /**
     * The cryptographic parameters are valid but unsupported by the server.
     */
    UnsupportedCryptographicParameters(0x0000003E),

    /**
     * The operation cannot be performed with the provided protocol version.
     */
    UnsupportedProtocolVersion(0x0000003F),

    /**
     * The Wrapping Object is archived.
     */
    WrappingObjectArchived(0x00000040),

    /**
     * The Wrapping Object exists, but is destroyed.
     */
    WrappingObjectDestroyed(0x00000041),

    /**
     * The Wrapping Object does not exist.
     */
    WrappingObjectNotFound(0x00000042),

    /**
     * The key lifecycle state is invalid for the operation, for example not Active for an Encrypt operation.
     */
    WrongKeyLifecycleState(0x00000043),

    /**
     * The operation could not be completed with the protections requested (or defaulted).
     */
    ProtectionStorageUnavailable(0x00000044),

    /**
     * There is a codec error in the PKCS#11 input parameter.
     */
    PKCS11CodecError(0x00000045),

    /**
     * The PKCS#11 function is invalid or unsupported.
     */
    PKCS11InvalidFunction(0x00000046),

    /**
     * The PKCS#11 interface is unknown or unavailable.
     */
    PKCS11InvalidInterface(0x00000047),

    /**
     * The operation could not be completed with the protections requested (or defaulted).
     */
    PrivateProtectionStorageUnavailable(0x00000048),

    /**
     * The operation could not be completed with the protections requested (or defaulted).
     */
    PublicProtectionStorageUnavailable(0x00000049),

    /**
     * <insert>
     */
    UnknownObjectGroup(0x0000004A),

    /**
     * The request failed because one or more constraints were violated.
     */
    ConstraintViolation(0x0000004B),

    /**
     * The asynchronous request specified was already processed.
     */
    DuplicateProcessRequest(0x0000004C),

    /**
     * The request failed for a reason other than the defined reasons above
     */
    GeneralFailure(0x00000100);

    private final int value;

    KMIPResultReason(int value)
    {
        this.value = value;
    }

    public int getValue()
    {
        return value;
    }

    public static KMIPResultReason fromValue(int value)
    {
        for (KMIPResultReason algorithm : KMIPResultReason.values())
        {
            if (algorithm.value == value)
            {
                return algorithm;
            }
        }
        throw new IllegalArgumentException("Unknown cryptographic algorithm value: " + value);
    }
}

