/*
 * This file is part of libaacs
 * Copyright (C) 2009-2010  Obliter0n
 * Copyright (C) 2009-2013  npzacz
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef AACS_H_
#define AACS_H_

#include <stdint.h>
#include <string>

#ifndef AACS_PUBLIC
#  define AACS_PUBLIC
#endif

#if !defined(_MSC_VER) && !defined(__cdecl)
#define __cdecl
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * aacs_open_device() error codes
 */
#define AACS_SUCCESS               0 /* no errors */
#define AACS_ERROR_CORRUPTED_DISC -1 /* opening or reading of AACS files failed */
#define AACS_ERROR_NO_CONFIG      -2 /* missing config file */
#define AACS_ERROR_NO_PK          -3 /* no matching processing key */
#define AACS_ERROR_NO_CERT        -4 /* no valid certificate */
#define AACS_ERROR_CERT_REVOKED   -5 /* certificate has been revoked */
#define AACS_ERROR_MMC_OPEN       -6 /* MMC open failed (no MMC drive ?) */
#define AACS_ERROR_MMC_FAILURE    -7 /* MMC failed */
#define AACS_ERROR_NO_DK          -8 /* no matching device key */

/**
 * Opaque type for AACS object
 */
typedef struct aacs AACS;

/**
 * Get version of AACS library.
 *
 * @param major  where to store libaacs major version
 * @param minor  where to store libaacs minor version
 * @param micro  where to store libaacs micro version
 */
AACS_PUBLIC void __cdecl aacs_get_version(int *major, int *minor, int *micro);

/*
 * open / close a disc
 */

/**
 * Initialize an AACS object.
 *
 * Disc must be opened with aacs_open_device().
 *
 * @return  AACS object, NULL on error
 */
AACS_PUBLIC AACS * __cdecl aacs_init(void);

/**
 * Open AACS disc / device.
 *
 * If device is not accessible (reading from .iso file or network stream),
 * path can be NULL.
 *
 * If files stored in AACS/ are not accessible from the file system (ex. unmounted disc),
 * application should provide file system access for libaacs (see aacs_set_fopen()).
 *
 * @param  aacs  AACS object
 * @param  path  path to device or disc root or NULL
 * @param  keyfile_path  optional path to AACS key file
 * @return  AACS_SUCCESS or ACS_ERROR_* error code
 */
AACS_PUBLIC int __cdecl aacs_open_device(AACS *, const char *path, const char *keyfile_path);

/* deprecated */
AACS_PUBLIC AACS * __cdecl aacs_open(const char *path, const char *keyfile_path);

/* deprecated */
AACS_PUBLIC AACS * __cdecl aacs_open2(const char *path, const char *keyfile_path, int *error_code);

/**
 * Closes and cleans up the AACS object.
 *
 * @param aacs  AACS object
 */
AACS_PUBLIC void __cdecl aacs_close(AACS *aacs);

/*
 * decryption
 */

#define AACS_TITLE_FIRST_PLAY  0
#define AACS_TITLE_TOP_MENU    0xffff

/**
 * Select title (optional).
 *
 * Titles can be stored in different CPS units and use different encryption key.
 *
 * If current title is not set, CPS unit is autodetected (with minor performance cost).
 * If application does not provide current title to libaacs, current CPS unit
 * should be reset by selecting First Play title (0xffff) when a new playlist is
 * started.
 *
 * @param aacs  AACS object
 * @param title  Current title from disc index
 */
AACS_PUBLIC void __cdecl aacs_select_title(AACS *aacs, uint32_t title_number);

/**
 * Decrypt data unit
 *
 * Remove possible bus encryption and AACS encryption.
 *
 * NOTE: only units from the same CPS unit may be decrypted in paraller.
 *
 * @param aacs  AACS object
 * @param buf  unit to decrypt
 * @return  1 on success, 0 on error
 */
AACS_PUBLIC int __cdecl aacs_decrypt_unit(AACS *aacs, uint8_t *buf);

/**
 * Remove bus encryption.
 *
 * If bus encryption is used, remove bus encryption.
 * Like aacs_decrypt_unit(), but does not perform AACS decryption.
 *
 * @param aacs  AACS object
 * @param buf  unit to decrypt
 * @return  1 on success, 0 on error
 */
AACS_PUBLIC int __cdecl aacs_decrypt_bus(AACS *aacs, uint8_t *buf);

/*
 * Disc information
 */
AACS_PUBLIC int __cdecl aacs_get_mkb_version(AACS *aacs);
AACS_PUBLIC const uint8_t * __cdecl aacs_get_disc_id(AACS *aacs);
AACS_PUBLIC const uint8_t * __cdecl aacs_get_vid(AACS *aacs);  /* may fail even if disc can be decrypted */
AACS_PUBLIC const uint8_t * __cdecl aacs_get_pmsn(AACS *aacs); /* may fail even if disc can be decrypted */
AACS_PUBLIC const uint8_t * __cdecl aacs_get_mk(AACS *aacs);   /* may fail even if disc can be decrypted */
AACS_PUBLIC const uint8_t * __cdecl aacs_get_content_cert_id(AACS *aacs);
AACS_PUBLIC const uint8_t * __cdecl aacs_get_bdj_root_cert_hash(AACS *aacs);

/*
 * AACS Online
 */
AACS_PUBLIC const uint8_t * __cdecl aacs_get_device_binding_id(AACS *aacs);
AACS_PUBLIC const uint8_t * __cdecl aacs_get_device_nonce(AACS *aacs);

/*
 * Revocation lists
 */
typedef struct {
    uint16_t  range;
    uint8_t   id[6];
} AACS_RL_ENTRY;

AACS_PUBLIC AACS_RL_ENTRY * __cdecl aacs_get_hrl(int *num_entries, int *mkb_version);
AACS_PUBLIC AACS_RL_ENTRY * __cdecl aacs_get_drl(int *num_entries, int *mkb_version);
AACS_PUBLIC void            __cdecl aacs_free_rl(AACS_RL_ENTRY **rl);

/*
 * Bus encryption information
 */

#define AACS_BUS_ENCRYPTION_ENABLED  0x01  /* Bus encryption enabled in the media */
#define AACS_BUS_ENCRYPTION_CAPABLE  0x02  /* Bus encryption capable drive */

AACS_PUBLIC uint32_t __cdecl aacs_get_bus_encryption(AACS *);

/*
 * Copy Control Information
 */

struct aacs_basic_cci;

AACS_PUBLIC struct aacs_basic_cci * __cdecl aacs_get_basic_cci(AACS *, uint32_t title);

AACS_PUBLIC void __cdecl aacs_set_fopen(AACS *aacs, void *bd_disc_structure_pointer, void* p);
AACS_PUBLIC void* __cdecl aacs_register_file(void* p);

#ifdef __cplusplus
}
#endif

typedef struct bd_mutex_s BD_MUTEX;
struct bd_mutex_s {
    void *impl;
};


typedef void    (*fptr_void)(...);
typedef int     (*fptr_int)(...);
typedef int32_t (*fptr_int32)(...);
typedef void*   (*fptr_p_void)(...);

typedef struct bd_aacs BD_AACS;

struct bd_aacs {
    void           *h_libaacs;   /* library handle from dlopen */
    void           *aacs;        /* aacs handle from aacs_open() */

    const uint8_t *disc_id;
    uint32_t       mkbv;

    /* function pointers */
    fptr_int       decrypt_unit;
    fptr_int       decrypt_bus;

    int            impl_id;
};

typedef struct bd_bdplus BD_BDPLUS;

struct bd_bdplus {
    void           *h_libbdplus; /* library handle from dlopen */

    void           *bdplus;      /* bdplus handle from bdplus_open() */

    /* functions */
    fptr_int32     event;
    fptr_p_void    m2ts;
    fptr_int32     m2ts_close;
    fptr_int32     seek;
    fptr_int32     fixup;

    /* old API */
    fptr_p_void    title;

    int impl_id;
};

typedef struct bd_dec BD_DEC;
struct bd_dec {
    int        use_menus;
    BD_AACS   *aacs;
    BD_BDPLUS *bdplus;
};

typedef struct bd_file_s BD_FILE_H;
struct bd_file_s
{
    void* internal;
    void    (*close) (BD_FILE_H *file);
    int64_t (*seek)  (BD_FILE_H *file, int64_t offset, int32_t origin);
    int64_t (*tell)  (BD_FILE_H *file);
    int     (*eof)   (BD_FILE_H *file);
    int64_t (*read)  (BD_FILE_H *file, uint8_t *buf, int64_t size);
    int64_t (*write) (BD_FILE_H *file, const uint8_t *buf, int64_t size);
};

typedef struct
{
    char    d_name[256];
} BD_DIRENT;

typedef struct bd_dir_s BD_DIR_H;
struct bd_dir_s
{
    void* internal;
    void (*close)(BD_DIR_H *dir);
    int (*read)(BD_DIR_H *dir, BD_DIRENT *entry);
};

typedef struct bd_disc BD_DISC;

struct bd_disc {
    BD_MUTEX  ovl_mutex;     /* protect access to overlay root */
    BD_MUTEX  properties_mutex; /* protect access to properties file */

    char     *disc_root;     /* disc filesystem root (if disc is mounted) */
    char     *overlay_root;  /* overlay filesystem root (if set) */

    BD_DEC   *dec;

    void         *fs_handle;
    BD_FILE_H * (*pf_file_open_bdrom)(void *, const char *);
    BD_DIR_H *  (*pf_dir_open_bdrom)(void *, const char *);
    void        (*pf_fs_close)(void *);

    const char   *udf_volid;
    char         *properties_file;  /* NULL if not yet used */

    int8_t        avchd;  /* -1 - unknown. 0 - no. 1 - yes */
};

static std::string *cxx_string_pointer;  // declare a persistent file scope variable

#endif /* AACS_H_ */
