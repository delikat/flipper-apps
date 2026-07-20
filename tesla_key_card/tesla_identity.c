#include "tesla_identity.h"

#include "tesla_secure.h"

#include <furi.h>
#include <furi_hal_crypto.h>
#include <furi_hal_random.h>
#include <storage/storage.h>
#include <toolbox/crc32_calc.h>

#include <mbedtls/md.h>

#include <stddef.h>
#include <string.h>

#define TAG "TeslaIdentity"

#define TESLA_IDENTITY_PATH           APP_DATA_PATH("identity.bin")
#define TESLA_IDENTITY_TMP_PATH       APP_DATA_PATH("identity.tmp")
#define TESLA_IDENTITY_VERSION        2U
#define TESLA_IDENTITY_LEGACY_VERSION 1U
#define TESLA_IDENTITY_MAC_SIZE       32U

typedef struct {
    uint8_t magic[8];
    uint8_t version;
    uint8_t uid_size;
    uint8_t uid[TESLA_NFC_UID_SIZE];
    uint8_t reserved[2];
    uint8_t iv[16];
    uint8_t encrypted_private_key[TESLA_PRIVATE_KEY_SIZE];
    uint8_t mac[TESLA_IDENTITY_MAC_SIZE];
} FURI_PACKED TeslaIdentityRecord;

typedef struct {
    uint8_t magic[8];
    uint8_t version;
    uint8_t uid_size;
    uint8_t uid[TESLA_NFC_UID_SIZE];
    uint8_t reserved[2];
    uint8_t iv[16];
    uint8_t encrypted_private_key[TESLA_PRIVATE_KEY_SIZE];
    uint32_t checksum;
} FURI_PACKED TeslaIdentityLegacyRecord;

static const uint8_t tesla_identity_magic[8] = {'T', 'K', 'C', 'F', 'Z', '0', '0', '1'};

static const uint8_t tesla_identity_mac_derivation[32] = {
    'T', 'e', 's', 'l', 'a', 'K', 'e', 'y', 'C', 'a', 'r', 'd', '-', 'M', 'A', 'C',
    '-', 'D', 'e', 'r', 'i', 'v', 'a', 't', 'i', 'o', 'n', '-', 'V', '1', 0,   0,
};

_Static_assert(
    offsetof(TeslaIdentityRecord, mac) % 16U == 0U,
    "Tesla identity MAC input must be AES-block aligned");

static bool tesla_identity_derive_mac_key(uint8_t mac_key[TESLA_IDENTITY_MAC_SIZE]) {
    static const uint8_t iv[16] = {0};
    bool success = false;
    bool enclave_loaded = false;

    if(!furi_hal_crypto_enclave_ensure_key(FURI_HAL_CRYPTO_ENCLAVE_UNIQUE_KEY_SLOT)) {
        goto cleanup;
    }
    if(!furi_hal_crypto_enclave_load_key(FURI_HAL_CRYPTO_ENCLAVE_UNIQUE_KEY_SLOT, iv)) {
        goto cleanup;
    }
    enclave_loaded = true;
    success = furi_hal_crypto_encrypt(
        tesla_identity_mac_derivation, mac_key, sizeof(tesla_identity_mac_derivation));

cleanup:
    if(enclave_loaded) {
        success = furi_hal_crypto_enclave_unload_key(FURI_HAL_CRYPTO_ENCLAVE_UNIQUE_KEY_SLOT) &&
                  success;
    }
    if(!success) tesla_secure_zero(mac_key, TESLA_IDENTITY_MAC_SIZE);
    return success;
}

static bool tesla_identity_calculate_mac(
    const TeslaIdentityRecord* record,
    uint8_t mac[TESLA_IDENTITY_MAC_SIZE]) {
    uint8_t mac_key[TESLA_IDENTITY_MAC_SIZE] = {0};
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    const bool success = md_info && tesla_identity_derive_mac_key(mac_key) &&
                         mbedtls_md_hmac(
                             md_info,
                             mac_key,
                             sizeof(mac_key),
                             (const uint8_t*)record,
                             offsetof(TeslaIdentityRecord, mac),
                             mac) == 0;
    tesla_secure_zero(mac_key, sizeof(mac_key));
    if(!success) tesla_secure_zero(mac, TESLA_IDENTITY_MAC_SIZE);
    return success;
}

static bool tesla_identity_mac_equals(
    const uint8_t first[TESLA_IDENTITY_MAC_SIZE],
    const uint8_t second[TESLA_IDENTITY_MAC_SIZE]) {
    volatile uint8_t difference = 0;
    for(size_t i = 0; i < TESLA_IDENTITY_MAC_SIZE; ++i) {
        difference |= first[i] ^ second[i];
    }
    return difference == 0U;
}

static uint32_t tesla_identity_legacy_checksum(const TeslaIdentityLegacyRecord* record) {
    return crc32_calc_buffer(0, record, offsetof(TeslaIdentityLegacyRecord, checksum));
}

void tesla_identity_clear(TeslaIdentity* identity) {
    if(identity) tesla_secure_zero(identity, sizeof(TeslaIdentity));
}

void tesla_identity_generate_uid(uint8_t uid[TESLA_NFC_UID_SIZE]) {
    furi_hal_random_fill_buf(uid, TESLA_NFC_UID_SIZE);
    uid[0] = 0x08U;
}

static TeslaIdentityLoadResult
    tesla_identity_read_record(Storage* storage, const char* path, TeslaIdentityRecord* record) {
    FileInfo file_info;
    const FS_Error stat_error = storage_common_stat(storage, path, &file_info);

    if(stat_error == FSE_NOT_EXIST) return TeslaIdentityLoadNotFound;
    if(stat_error != FSE_OK || file_info.size != sizeof(TeslaIdentityRecord)) {
        return stat_error == FSE_OK ? TeslaIdentityLoadCorrupt : TeslaIdentityLoadStorageError;
    }

    File* file = storage_file_alloc(storage);
    if(!storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        storage_file_free(file);
        return TeslaIdentityLoadStorageError;
    }

    const size_t bytes_read = storage_file_read(file, record, sizeof(*record));
    storage_file_close(file);
    storage_file_free(file);
    return bytes_read == sizeof(*record) ? TeslaIdentityLoadOk : TeslaIdentityLoadStorageError;
}

static TeslaIdentityLoadResult tesla_identity_read_legacy_record(
    Storage* storage,
    const char* path,
    TeslaIdentityLegacyRecord* record) {
    FileInfo file_info;
    const FS_Error stat_error = storage_common_stat(storage, path, &file_info);

    if(stat_error == FSE_NOT_EXIST) return TeslaIdentityLoadNotFound;
    if(stat_error != FSE_OK || file_info.size != sizeof(TeslaIdentityLegacyRecord)) {
        return stat_error == FSE_OK ? TeslaIdentityLoadCorrupt : TeslaIdentityLoadStorageError;
    }

    File* file = storage_file_alloc(storage);
    if(!storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        storage_file_free(file);
        return TeslaIdentityLoadStorageError;
    }

    const size_t bytes_read = storage_file_read(file, record, sizeof(*record));
    storage_file_close(file);
    storage_file_free(file);
    return bytes_read == sizeof(*record) ? TeslaIdentityLoadOk : TeslaIdentityLoadStorageError;
}

static TeslaIdentityLoadResult tesla_identity_decrypt_private_key(
    const uint8_t iv[16],
    const uint8_t encrypted_private_key[TESLA_PRIVATE_KEY_SIZE],
    TeslaIdentity* identity) {
    if(!furi_hal_crypto_enclave_ensure_key(FURI_HAL_CRYPTO_ENCLAVE_UNIQUE_KEY_SLOT) ||
       !furi_hal_crypto_enclave_load_key(FURI_HAL_CRYPTO_ENCLAVE_UNIQUE_KEY_SLOT, iv)) {
        return TeslaIdentityLoadCryptoError;
    }

    const bool decrypted = furi_hal_crypto_decrypt(
        encrypted_private_key, identity->private_key, TESLA_PRIVATE_KEY_SIZE);
    const bool unloaded =
        furi_hal_crypto_enclave_unload_key(FURI_HAL_CRYPTO_ENCLAVE_UNIQUE_KEY_SLOT);
    if(!decrypted || !unloaded) {
        tesla_identity_clear(identity);
        return TeslaIdentityLoadCryptoError;
    }
    return TeslaIdentityLoadOk;
}

static TeslaIdentityLoadResult
    tesla_identity_decode_record(const TeslaIdentityRecord* record, TeslaIdentity* identity) {
    uint8_t calculated_mac[TESLA_IDENTITY_MAC_SIZE] = {0};

    if(memcmp(record->magic, tesla_identity_magic, sizeof(record->magic)) != 0 ||
       record->version != TESLA_IDENTITY_VERSION || record->uid_size != TESLA_NFC_UID_SIZE) {
        return TeslaIdentityLoadCorrupt;
    }
    if(!tesla_identity_calculate_mac(record, calculated_mac)) {
        return TeslaIdentityLoadCryptoError;
    }
    if(!tesla_identity_mac_equals(record->mac, calculated_mac)) {
        tesla_secure_zero(calculated_mac, sizeof(calculated_mac));
        return TeslaIdentityLoadCorrupt;
    }
    tesla_secure_zero(calculated_mac, sizeof(calculated_mac));

    const TeslaIdentityLoadResult decrypt_result =
        tesla_identity_decrypt_private_key(record->iv, record->encrypted_private_key, identity);
    if(decrypt_result != TeslaIdentityLoadOk) return decrypt_result;

    memcpy(identity->uid, record->uid, TESLA_NFC_UID_SIZE);
    return TeslaIdentityLoadOk;
}

static TeslaIdentityLoadResult tesla_identity_decode_legacy_record(
    const TeslaIdentityLegacyRecord* record,
    TeslaIdentity* identity) {
    if(memcmp(record->magic, tesla_identity_magic, sizeof(record->magic)) != 0 ||
       record->version != TESLA_IDENTITY_LEGACY_VERSION ||
       record->uid_size != TESLA_NFC_UID_SIZE ||
       record->checksum != tesla_identity_legacy_checksum(record)) {
        return TeslaIdentityLoadCorrupt;
    }

    const TeslaIdentityLoadResult decrypt_result =
        tesla_identity_decrypt_private_key(record->iv, record->encrypted_private_key, identity);
    if(decrypt_result != TeslaIdentityLoadOk) return decrypt_result;

    memcpy(identity->uid, record->uid, TESLA_NFC_UID_SIZE);
    return TeslaIdentityLoadOk;
}

static TeslaIdentityLoadResult tesla_identity_load_path(
    Storage* storage,
    const char* path,
    TeslaIdentity* identity,
    bool* legacy_record) {
    furi_assert(legacy_record);
    *legacy_record = false;

    TeslaIdentityRecord record = {0};
    TeslaIdentityLoadResult result = tesla_identity_read_record(storage, path, &record);
    if(result == TeslaIdentityLoadOk) {
        result = tesla_identity_decode_record(&record, identity);
        tesla_secure_zero(&record, sizeof(record));
        return result;
    }
    tesla_secure_zero(&record, sizeof(record));
    if(result != TeslaIdentityLoadCorrupt) return result;

    TeslaIdentityLegacyRecord legacy = {0};
    result = tesla_identity_read_legacy_record(storage, path, &legacy);
    if(result == TeslaIdentityLoadOk) {
        result = tesla_identity_decode_legacy_record(&legacy, identity);
        *legacy_record = result == TeslaIdentityLoadOk;
    }
    tesla_secure_zero(&legacy, sizeof(legacy));
    return result;
}

TeslaIdentityLoadResult tesla_identity_load(TeslaIdentity* identity) {
    furi_assert(identity);
    tesla_identity_clear(identity);

    Storage* storage = furi_record_open(RECORD_STORAGE);
    bool legacy_record = false;
    TeslaIdentityLoadResult result =
        tesla_identity_load_path(storage, TESLA_IDENTITY_PATH, identity, &legacy_record);

    if(result == TeslaIdentityLoadNotFound || result == TeslaIdentityLoadCorrupt) {
        bool temporary_legacy_record = false;
        TeslaIdentityLoadResult temporary_result = tesla_identity_load_path(
            storage, TESLA_IDENTITY_TMP_PATH, identity, &temporary_legacy_record);

        if(temporary_result == TeslaIdentityLoadOk) {
            result = TeslaIdentityLoadOk;
            if(storage_common_rename(storage, TESLA_IDENTITY_TMP_PATH, TESLA_IDENTITY_PATH) !=
               FSE_OK) {
                FURI_LOG_W(TAG, "Recovered staged identity; rename failed");
                temporary_legacy_record = false;
            }
            legacy_record = temporary_legacy_record;
        } else if(result == TeslaIdentityLoadNotFound) {
            result = temporary_result;
        }
    }

    furi_record_close(RECORD_STORAGE);

    if(result == TeslaIdentityLoadOk && legacy_record) {
        FURI_LOG_W(TAG, "Legacy identity retained; reset to upgrade storage");
    }
    return result;
}

bool tesla_identity_save(const TeslaIdentity* identity) {
    furi_assert(identity);

    bool success = false;
    bool enclave_loaded = false;
    TeslaIdentityRecord record = {0};
    memcpy(record.magic, tesla_identity_magic, sizeof(record.magic));
    record.version = TESLA_IDENTITY_VERSION;
    record.uid_size = TESLA_NFC_UID_SIZE;
    memcpy(record.uid, identity->uid, TESLA_NFC_UID_SIZE);
    furi_hal_random_fill_buf(record.iv, sizeof(record.iv));

    if(!furi_hal_crypto_enclave_ensure_key(FURI_HAL_CRYPTO_ENCLAVE_UNIQUE_KEY_SLOT)) {
        FURI_LOG_E(TAG, "Unable to provision device key");
        goto cleanup_record;
    }
    if(!furi_hal_crypto_enclave_load_key(FURI_HAL_CRYPTO_ENCLAVE_UNIQUE_KEY_SLOT, record.iv)) {
        FURI_LOG_E(TAG, "Unable to load device key");
        goto cleanup_record;
    }
    enclave_loaded = true;

    if(!furi_hal_crypto_encrypt(
           identity->private_key, record.encrypted_private_key, TESLA_PRIVATE_KEY_SIZE)) {
        FURI_LOG_E(TAG, "Private-key encryption failed");
        goto cleanup_record;
    }
    if(!furi_hal_crypto_enclave_unload_key(FURI_HAL_CRYPTO_ENCLAVE_UNIQUE_KEY_SLOT)) {
        enclave_loaded = false;
        FURI_LOG_E(TAG, "Unable to unload device key");
        goto cleanup_record;
    }
    enclave_loaded = false;
    if(!tesla_identity_calculate_mac(&record, record.mac)) {
        FURI_LOG_E(TAG, "Unable to authenticate identity record");
        goto cleanup_record;
    }

    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_common_remove(storage, TESLA_IDENTITY_TMP_PATH);
    File* file = storage_file_alloc(storage);

    if(storage_file_open(file, TESLA_IDENTITY_TMP_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        const size_t bytes_written = storage_file_write(file, &record, sizeof(record));
        const bool synced = bytes_written == sizeof(record) && storage_file_sync(file);
        storage_file_close(file);

        if(synced && storage_common_rename(
                         storage, TESLA_IDENTITY_TMP_PATH, TESLA_IDENTITY_PATH) == FSE_OK) {
            success = true;
        }
    }

    storage_file_free(file);
    if(!success) storage_common_remove(storage, TESLA_IDENTITY_TMP_PATH);
    furi_record_close(RECORD_STORAGE);

cleanup_record:
    if(enclave_loaded) {
        furi_hal_crypto_enclave_unload_key(FURI_HAL_CRYPTO_ENCLAVE_UNIQUE_KEY_SLOT);
    }
    tesla_secure_zero(&record, sizeof(record));
    return success;
}

bool tesla_identity_delete(void) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    const FS_Error error = storage_common_remove(storage, TESLA_IDENTITY_PATH);
    storage_common_remove(storage, TESLA_IDENTITY_TMP_PATH);
    furi_record_close(RECORD_STORAGE);
    return error == FSE_OK || error == FSE_NOT_EXIST;
}
