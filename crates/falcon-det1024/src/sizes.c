/*
 * The sizes the library's headers compute, as functions Rust can call.
 *
 * Every buffer this crate hands to Falcon is a fixed-size Rust array, so the sizes are declared
 * twice: once by the C macros, once by the constants in lib.rs. These accessors let a test compare
 * them, which is what would catch a submodule bumped to a version that changed one.
 */

#include <stddef.h>

#include "deterministic.h"
#include "falcon.h"

size_t falcon_det1024_rs_pubkey_size(void) { return FALCON_DET1024_PUBKEY_SIZE; }

size_t falcon_det1024_rs_privkey_size(void) { return FALCON_DET1024_PRIVKEY_SIZE; }

size_t falcon_det1024_rs_sig_compressed_maxsize(void) {
	return FALCON_DET1024_SIG_COMPRESSED_MAXSIZE;
}

size_t falcon_det1024_rs_shake256_context_size(void) { return sizeof(shake256_context); }

unsigned falcon_det1024_rs_sig_compressed_header(void) {
	return FALCON_DET1024_SIG_COMPRESSED_HEADER;
}

unsigned falcon_det1024_rs_current_salt_version(void) {
	return FALCON_DET1024_CURRENT_SALT_VERSION;
}
