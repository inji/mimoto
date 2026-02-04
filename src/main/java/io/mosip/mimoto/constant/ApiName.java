package io.mosip.mimoto.constant;

/**
 * The Enum ApiName.
 *
 * @author Rishabh Keshari
 */
public enum ApiName {

    /** The auth. */
    AUTH,

    /** The authinternal. */
    AUTHINTERNAL,

    /** The master data. */
    MASTER,

    AUDIT,

    /** The ida. */
    IDA,

    /** The idrepository. */
    IDREPOSITORY,

    /** The idrepository get id by uin. */
    IDREPOGETIDBYUIN,

    /** The uingenerator. */
    UINGENERATOR,

    /** The idrepodev. */
    IDREPODEV,

    /** The Cryptomaanger *. */
    CRYPTOMANAGERDECRYPT,

    ENCRYPTURL,

    IDAUTHENCRYPTION,

    IDAUTHPUBLICKEY,

    /** The ReverseDataSync *. */
    REVERSEDATASYNC,

    /** The Device history *. */
    DEVICESHISTORIES,

    /** The Reg center device history *. */
    REGISTRATIONCENTERDEVICEHISTORY,

    /** The registration center timestamp *. */
    REGISTRATIONCENTERTIMESTAMP,

    /** The registration connector *. */
    REGISTRATIONCONNECTOR,

    /** The encryptionservice. */
    ENCRYPTIONSERVICE,

    /** The ridgeneration. */
    RIDGENERATION,

    /** The retrieveidentity. */
    RETRIEVEIDENTITY,

    /** The retrieveidentity using rid. */
    RETRIEVEIDENTITYFROMRID,

    /** The digitalsignature. */
    DIGITALSIGNATURE,

    /** The Vid creation. */
    CREATEVID,

    /** The user details. */
    USERDETAILS,

    /** get operator rid from id. */
    GETRIDFROMUSERID,

    /** The internalauth. */
    INTERNALAUTH,

    /** The templates. */
    TEMPLATES,

    GETUINBYVID,

    DEVICEVALIDATEHISTORY,

    DECRYPTPINBASSED, CREATEDATASHARE,

    NGINXDMZURL,

    IDSCHEMAURL,

    RESIDENT_OTP,
    RESIDENT_VID,
    RESIDENT_CREDENTIAL_REQUEST,
    RESIDENT_CREDENTIAL_REQUEST_STATUS,
    RESIDENT_AUTH_LOCK,
    RESIDENT_AUTH_UNLOCK,
    RESIDENT_INDIVIDUALID_OTP,
    RESIDENT_AID_GET_INDIVIDUALID,

    IDP_LINK_TRANSACTION,
    IDP_AUTHENTICATE,
    IDP_CONSENT,
    IDP_OTP,
    BINDING_OTP,
    WALLET_BINDING,

    WALLET_BINDING_GLOBALID,

    BINDING_OTP_GLOBALID
}
