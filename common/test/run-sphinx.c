#include "../sphinx.c"
#include <secp256k1.h>
#include <ccan/opt/opt.h>
#include <ccan/short_types/short_types.h>
#include <string.h>
#include <ccan/str/hex/hex.h>
#include <common/sphinx.h>
#include <common/utils.h>
#include <err.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>

/* AUTOGENERATED MOCKS START */
/* Generated stub for amount_asset_is_main */
bool amount_asset_is_main(struct amount_asset *asset UNNEEDED)
{ fprintf(stderr, "amount_asset_is_main called!\n"); abort(); }
/* Generated stub for amount_asset_to_sat */
struct amount_sat amount_asset_to_sat(struct amount_asset *asset UNNEEDED)
{ fprintf(stderr, "amount_asset_to_sat called!\n"); abort(); }
/* Generated stub for amount_sat_add */
 bool amount_sat_add(struct amount_sat *val UNNEEDED,
				       struct amount_sat a UNNEEDED,
				       struct amount_sat b UNNEEDED)
{ fprintf(stderr, "amount_sat_add called!\n"); abort(); }
/* Generated stub for amount_sat_eq */
bool amount_sat_eq(struct amount_sat a UNNEEDED, struct amount_sat b UNNEEDED)
{ fprintf(stderr, "amount_sat_eq called!\n"); abort(); }
/* Generated stub for amount_sat_sub */
 bool amount_sat_sub(struct amount_sat *val UNNEEDED,
				       struct amount_sat a UNNEEDED,
				       struct amount_sat b UNNEEDED)
{ fprintf(stderr, "amount_sat_sub called!\n"); abort(); }
/* Generated stub for bigsize_get */
size_t bigsize_get(const u8 *p UNNEEDED, size_t max UNNEEDED, bigsize_t *val UNNEEDED)
{ fprintf(stderr, "bigsize_get called!\n"); abort(); }
/* Generated stub for bigsize_put */
size_t bigsize_put(u8 buf[BIGSIZE_MAX_LEN] UNNEEDED, bigsize_t v UNNEEDED)
{ fprintf(stderr, "bigsize_put called!\n"); abort(); }
/* Generated stub for fromwire */
const u8 *fromwire(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, void *copy UNNEEDED, size_t n UNNEEDED)
{ fprintf(stderr, "fromwire called!\n"); abort(); }
/* Generated stub for fromwire_amount_msat */
struct amount_msat fromwire_amount_msat(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_amount_msat called!\n"); abort(); }
/* Generated stub for fromwire_bigsize */
bigsize_t fromwire_bigsize(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_bigsize called!\n"); abort(); }
/* Generated stub for fromwire_fail */
const void *fromwire_fail(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_fail called!\n"); abort(); }
/* Generated stub for fromwire_sha256 */
void fromwire_sha256(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, struct sha256 *sha256 UNNEEDED)
{ fprintf(stderr, "fromwire_sha256 called!\n"); abort(); }
/* Generated stub for fromwire_short_channel_id */
void fromwire_short_channel_id(const u8 **cursor UNNEEDED, size_t *max UNNEEDED,
			       struct short_channel_id *short_channel_id UNNEEDED)
{ fprintf(stderr, "fromwire_short_channel_id called!\n"); abort(); }
/* Generated stub for fromwire_tlvs */
bool fromwire_tlvs(const u8 **cursor UNNEEDED, size_t *max UNNEEDED,
		   const struct tlv_record_type types[] UNNEEDED,
		   size_t num_types UNNEEDED,
		   void *record UNNEEDED)
{ fprintf(stderr, "fromwire_tlvs called!\n"); abort(); }
/* Generated stub for fromwire_tu32 */
u32 fromwire_tu32(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_tu32 called!\n"); abort(); }
/* Generated stub for fromwire_tu64 */
u64 fromwire_tu64(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_tu64 called!\n"); abort(); }
/* Generated stub for fromwire_u16 */
u16 fromwire_u16(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u16 called!\n"); abort(); }
/* Generated stub for fromwire_u32 */
u32 fromwire_u32(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u32 called!\n"); abort(); }
/* Generated stub for fromwire_u8 */
u8 fromwire_u8(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u8 called!\n"); abort(); }
/* Generated stub for fromwire_u8_array */
void fromwire_u8_array(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, u8 *arr UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "fromwire_u8_array called!\n"); abort(); }
/* Generated stub for towire */
void towire(u8 **pptr UNNEEDED, const void *data UNNEEDED, size_t len UNNEEDED)
{ fprintf(stderr, "towire called!\n"); abort(); }
/* Generated stub for towire_amount_msat */
void towire_amount_msat(u8 **pptr UNNEEDED, const struct amount_msat msat UNNEEDED)
{ fprintf(stderr, "towire_amount_msat called!\n"); abort(); }
/* Generated stub for towire_bigsize */
void towire_bigsize(u8 **pptr UNNEEDED, const bigsize_t val UNNEEDED)
{ fprintf(stderr, "towire_bigsize called!\n"); abort(); }
/* Generated stub for towire_pad */
void towire_pad(u8 **pptr UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "towire_pad called!\n"); abort(); }
/* Generated stub for towire_sha256 */
void towire_sha256(u8 **pptr UNNEEDED, const struct sha256 *sha256 UNNEEDED)
{ fprintf(stderr, "towire_sha256 called!\n"); abort(); }
/* Generated stub for towire_short_channel_id */
void towire_short_channel_id(u8 **pptr UNNEEDED,
			     const struct short_channel_id *short_channel_id UNNEEDED)
{ fprintf(stderr, "towire_short_channel_id called!\n"); abort(); }
/* Generated stub for towire_tu32 */
void towire_tu32(u8 **pptr UNNEEDED, u32 v UNNEEDED)
{ fprintf(stderr, "towire_tu32 called!\n"); abort(); }
/* Generated stub for towire_tu64 */
void towire_tu64(u8 **pptr UNNEEDED, u64 v UNNEEDED)
{ fprintf(stderr, "towire_tu64 called!\n"); abort(); }
/* Generated stub for towire_u16 */
void towire_u16(u8 **pptr UNNEEDED, u16 v UNNEEDED)
{ fprintf(stderr, "towire_u16 called!\n"); abort(); }
/* Generated stub for towire_u32 */
void towire_u32(u8 **pptr UNNEEDED, u32 v UNNEEDED)
{ fprintf(stderr, "towire_u32 called!\n"); abort(); }
/* Generated stub for towire_u64 */
void towire_u64(u8 **pptr UNNEEDED, u64 v UNNEEDED)
{ fprintf(stderr, "towire_u64 called!\n"); abort(); }
/* Generated stub for towire_u8_array */
void towire_u8_array(u8 **pptr UNNEEDED, const u8 *arr UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "towire_u8_array called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */

secp256k1_context *secp256k1_ctx;

static struct secret secret_from_hex(const char *hex)
{
	struct secret s;
	if (!hex_decode(hex, strlen(hex), &s, sizeof(s)))
		abort();
	return s;
}

/* Create an onionreply with the test vector parameters and check that
 * we match the test vectors and that we can also unwrap it. */
static void run_unit_tests(void)
{
	struct onionreply *oreply;
	u8 *reply;
	u8 *raw = tal_hexdata(tmpctx, "2002", 4);

	/* Shared secrets we already have from the forward path */
	char *secrets[] = {
	    "53eb63ea8a3fec3b3cd433b85cd62a4b145e1dda09391b348c4e1cd36a03ea66",
	    "a6519e98832a0b179f62123b3567c106db99ee37bef036e783263602f3488fae",
	    "3a6b412548762f0dbccce5c7ae7bb8147d1caf9b5471c34120b30bc9c04891cc",
	    "21e13c2d7cfe7e18836df50872466117a295783ab8aab0e7ecc8c725503ad02d",
	    "b5756b9b542727dbafc6765a49488b023a725d631af688fc031217e90770c328",
	};
	struct secret ss[] = {
		secret_from_hex(secrets[0]),
		secret_from_hex(secrets[1]),
		secret_from_hex(secrets[2]),
		secret_from_hex(secrets[3]),
		secret_from_hex(secrets[4])
	};

	int replylen = 164 * 2;

	u8 *intermediates[] = {
	    tal_hexdata(tmpctx, "500d8596f76d3045bfdbf99914b98519fe76ea130dc223"
				"38c473ab68d74378b13a06a19f891145610741c83ad40b"
				"7712aefaddec8c6baf7325d92ea4ca4d1df8bce517f7e5"
				"4554608bf2bd8071a4f52a7a2f7ffbb1413edad81eeea5"
				"785aa9d990f2865dc23b4bc3c301a94eec4eabebca66be"
				"5cf638f693ec256aec514620cc28ee4a94bd9565bc4d49"
				"62b9d3641d4278fb319ed2b84de5b665f307a2db0f7fbb"
				"757366",
			replylen),
	    tal_hexdata(tmpctx, "669478a3ddf9ba4049df8fa51f73ac712b9c20380cda43"
				"1696963a492713ebddb7dfadbb566c8dae8857add94e67"
				"02fb4c3a4de22e2e669e1ed926b04447fc73034bb730f4"
				"932acd62727b75348a648a1128744657ca6a4e713b9b64"
				"6c3ca66cac02cdab44dd3439890ef3aaf61708714f7375"
				"349b8da541b2548d452d84de7084bb95b3ac2345201d62"
				"4d31f4d52078aa0fa05a88b4e20202bd2b86ac5b52919e"
				"a305a8",
			replylen),
	    tal_hexdata(tmpctx, "6984b0ccd86f37995857363df13670acd064bfd1a540e5"
				"21cad4d71c07b1bc3dff9ac25f41addfb7466e74f81b3e"
				"545563cdd8f5524dae873de61d7bdfccd496af2584930d"
				"2b566b4f8d3881f8c043df92224f38cf094cfc09d92655"
				"989531524593ec6d6caec1863bdfaa79229b5020acc034"
				"cd6deeea1021c50586947b9b8e6faa83b81fbfa6133c0a"
				"f5d6b07c017f7158fa94f0d206baf12dda6b68f785b773"
				"b360fd",
			replylen),
	    tal_hexdata(tmpctx, "08cd44478211b8a4370ab1368b5ffe8c9c92fb830ff4ad"
				"6e3b0a316df9d24176a081bab161ea0011585323930fa5"
				"b9fae0c85770a2279ff59ec427ad1bbff9001c0cd14970"
				"04bd2a0f68b50704cf6d6a4bf3c8b6a0833399a24b3456"
				"961ba00736785112594f65b6b2d44d9f5ea4e49b5e1ec2"
				"af978cbe31c67114440ac51a62081df0ed46d4a3df295d"
				"a0b0fe25c0115019f03f15ec86fabb4c852f83449e812f"
				"141a93",

			replylen),
	    tal_hexdata(tmpctx, "69b1e5a3e05a7b5478e6529cd1749fdd8c66da6f6db420"
				"78ff8497ac4e117e91a8cb9168b58f2fd45edd73c1b0c8"
				"b33002df376801ff58aaa94000bf8a86f92620f343baef"
				"38a580102395ae3abf9128d1047a0736ff9b83d456740e"
				"bbb4aeb3aa9737f18fb4afb4aa074fb26c4d702f429688"
				"88550a3bded8c05247e045b866baef0499f079fdaeef65"
				"38f31d44deafffdfd3afa2fb4ca9082b8f1c465371a989"
				"4dd8c2",
			replylen),
	};

	reply = create_onionreply(tmpctx, &ss[4], raw);
	for (int i = 4; i >= 0; i--) {
		printf("input_packet %s\n", tal_hex(tmpctx, reply));
		reply = wrap_onionreply(tmpctx, &ss[i], reply);
		printf("obfuscated_packet %s\n", tal_hex(tmpctx, reply));
		assert(memcmp(reply, intermediates[i], tal_count(reply)) == 0);
	}

	oreply = unwrap_onionreply(tmpctx, ss, 5, reply);
	printf("unwrapped %s\n", tal_hex(tmpctx, oreply->msg));
	assert(memcmp(raw, oreply->msg, tal_bytelen(raw)) == 0);
}

int main(int argc, char **argv)
{
	setup_locale();

	bool unit = false;

	secp256k1_ctx = secp256k1_context_create(
		SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
	setup_tmpctx();

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "--unit\n"
			   "Run unit tests against test vectors",
			   "Print this message.");
	opt_register_noarg("--unit",
			   opt_set_bool, &unit,
			   "Run unit tests against test vectors");

	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (unit) {
		run_unit_tests();
	}
	secp256k1_context_destroy(secp256k1_ctx);
	opt_free_table();
	tal_free(tmpctx);
	return 0;
}
