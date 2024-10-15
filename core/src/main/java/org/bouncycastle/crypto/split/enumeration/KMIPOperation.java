package org.bouncycastle.crypto.split.enumeration;

public enum KMIPOperation
    implements KMIPEnumeration
{
    CREATE(0x00000001),
    CREATE_KEY_PAIR(0x00000002),
    REGISTER(0x00000003),
    REKEY(0x00000004),
    DERIVE_KEY(0x00000005),
    CERTIFY(0x00000006),
    RECERTIFY(0x00000007),
    LOCATE(0x00000008),
    CHECK(0x00000009),
    GET(0x0000000A),
    GET_ATTRIBUTES(0x0000000B),
    GET_ATTRIBUTE_LIST(0x0000000C),
    ADD_ATTRIBUTE(0x0000000D),
    MODIFY_ATTRIBUTE(0x0000000E),
    DELETE_ATTRIBUTE(0x0000000F),
    OBTAIN_LEASE(0x00000010),
    GET_USAGE_ALLOCATION(0x00000011),
    ACTIVATE(0x00000012),
    REVOKE(0x00000013),
    DESTROY(0x00000014),
    ARCHIVE(0x00000015),
    RECOVER(0x00000016),
    VALIDATE(0x00000017),
    QUERY(0x00000018),
    CANCEL(0x00000019),
    POLL(0x0000001A),
    NOTIFY(0x0000001B),
    PUT(0x0000001C),
    REKEY_KEY_PAIR(0x0000001D),
    DISCOVER_VERSIONS(0x0000001E),
    ENCRYPT(0x0000001F),
    DECRYPT(0x00000020),
    SIGN(0x00000021),
    SIGNATURE_VERIFY(0x00000022),
    MAC(0x00000023),
    MAC_VERIFY(0x00000024),
    RNG_RETRIEVE(0x00000025),
    RNG_SEED(0x00000026),
    HASH(0x00000027),
    CREATE_SPLIT_KEY(0x00000028),
    JOIN_SPLIT_KEY(0x00000029),
    IMPORT(0x0000002A),
    EXPORT(0x0000002B),
    LOG(0x0000002C),
    LOGIN(0x0000002D),
    LOGOUT(0x0000002E),
    DELEGATED_LOGIN(0x0000002F),
    ADJUST_ATTRIBUTE(0x00000030),
    SET_ATTRIBUTE(0x00000031),
    SET_ENDPOINT_ROLE(0x00000032),
    PKCS11(0x00000033),
    INTEROP(0x00000034),
    RE_PROVISION(0x00000035),
    SET_DEFAULTS(0x00000036),
    SET_CONSTRAINTS(0x00000037),
    GET_CONSTRAINTS(0x00000038),
    QUERY_ASYNC_REQUESTS(0x00000039),
    PROCESS(0x0000003A),
    PING(0x0000003B);

    private final int value;

    KMIPOperation(int value)
    {
        this.value = value;
    }

    public int getValue()
    {
        return value;
    }

    public static KMIPOperation fromValue(int value)
    {
        for (KMIPOperation op : values())
        {
            if (op.value == value)
            {
                return op;
            }
        }
        throw new IllegalArgumentException("Invalid Operation value: " + value);
    }

    @Override
    public String toString()
    {
        return String.format("%s (0x%08X)", name(), value);
    }
}

