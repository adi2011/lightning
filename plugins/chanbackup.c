#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/err/err.h>
#include <ccan/json_out/json_out.h>
#include <ccan/noerr/noerr.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <common/features.h>
#include <common/hsm_encryption.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/scb_wiregen.h>
#include <common/type_to_string.h>
#include <errno.h>
#include <fcntl.h>
#include <plugins/libplugin.h>
#include <sodium.h>
#include <unistd.h>

#define HEADER_LEN crypto_secretstream_xchacha20poly1305_HEADERBYTES
#define ABYTES crypto_secretstream_xchacha20poly1305_ABYTES

#define FILENAME "emergency.recover"

/* VERSION is the current version of the data encrypted in the file */
#define VERSION ((u64)1)

/* Global secret object to keep the derived encryption key for the SCB */
static struct secret secret;

/* Helper to fetch out SCB from the RPC call */
static bool json_to_scb_chan(const char *buffer,
                        const jsmntok_t *tok,
		        struct scb_chan ***channels)
{
	size_t i;
	const jsmntok_t *t;
	*channels = tok->size ? tal_arr(tmpctx,
					struct scb_chan *,
					tok->size) : NULL;

	json_for_each_arr(i, t, tok) {
		const u8 *scb_tmp = tal_hexdata(tmpctx,
						json_strdup(tmpctx,
							    buffer,
							    t),
						strlen(json_strdup(tmpctx,
								   buffer,
								   t)));
		size_t scblen_tmp = tal_count(scb_tmp);

		(*channels)[i] = fromwire_scb_chan(tmpctx,
						   &scb_tmp,
						   &scblen_tmp);
	}

	return true;
}

/* This writes encrypted static backup in the recovery file */
static void write_scb(struct plugin *p,
                      int fd,
		      struct scb_chan **scb_chan_arr)
{
	u32 timestamp = time_now().ts.tv_sec;

	u8 *decrypted_scb = towire_static_chan_backup(tmpctx,
						      VERSION,
						      timestamp,
						      cast_const2(const struct scb_chan **,
						      		  scb_chan_arr));

	u8 *encrypted_scb = tal_arr(tmpctx,
                            u8,
                            tal_bytelen(decrypted_scb) +
                            ABYTES +
                            HEADER_LEN);

	crypto_secretstream_xchacha20poly1305_state crypto_state;

	if (crypto_secretstream_xchacha20poly1305_init_push(&crypto_state,
							    encrypted_scb,
							    (&secret)->data) != 0)
	{
		plugin_err(p, "Can't encrypt the data!");
		return;
	}

	if (crypto_secretstream_xchacha20poly1305_push(&crypto_state,
                                                encrypted_scb +
                                                HEADER_LEN,
                                                NULL, decrypted_scb,
                                                tal_bytelen(decrypted_scb),
                                                /* Additional data and tag */
                                                NULL, 0, 0)) {
		plugin_err(p, "Can't encrypt the data!");
		return;
	}

	if (!write_all(fd, encrypted_scb, tal_bytelen(encrypted_scb))) {
			unlink_noerr("scb.tmp");
			plugin_err(p, "Writing encrypted SCB: %s",
                                  strerror(errno));
	}

}

/* checks if the SCB file exists, creates a new one in case it doesn't. */
static void maybe_create_new_scb(struct plugin *p,
				 struct scb_chan **channels)
{

	/* Note that this is opened for write-only, even though the permissions
	 * are set to read-only.  That's perfectly valid! */
	int fd = open(FILENAME, O_CREAT|O_EXCL|O_WRONLY, 0400);
	if (fd < 0) {
		/* Don't do anything if the file already exists. */
		if (errno == EEXIST)
			return;
		plugin_err(p, "creating: %s", strerror(errno));
	}

	/* Comes here only if the file haven't existed before */
	unlink_noerr(FILENAME);

	/* This couldn't give EEXIST because we call unlink_noerr("scb.tmp")
	 * in INIT */
	fd = open("scb.tmp", O_CREAT|O_EXCL|O_WRONLY, 0400);
	if (fd < 0)
		plugin_err(p, "Opening: %s", strerror(errno));

	plugin_log(p, LOG_INFORM, "Creating Emergency Recovery");

	write_scb(p, fd, channels);

	/* fsync (mostly!) ensures that the file has reached the disk. */
	if (fsync(fd) != 0) {
		unlink_noerr("scb.tmp");
		plugin_err(p, "fsync : %s", strerror(errno));
	}

	/* This should never fail if fsync succeeded.  But paranoia good, and
	 * bugs exist. */
	if (close(fd) != 0) {
		unlink_noerr("scb.tmp");
		plugin_err(p, "closing: %s", strerror(errno));
	}

	/* We actually need to sync the *directory itself* to make sure the
	 * file exists!  You're only allowed to open directories read-only in
	 * modern Unix though. */
	fd = open(".", O_RDONLY);
	if (fd < 0)
		plugin_err(p, "Opening: %s", strerror(errno));

	if (fsync(fd) != 0) {
		unlink_noerr("scb.tmp");
		plugin_err(p, "closing: %s", strerror(errno));
	}

	/* This will never fail, if fsync worked! */
	close(fd);

	/* This will update the scb file */
	rename("scb.tmp", FILENAME);
}

static u8* get_file_data(struct plugin *p)
{
	u8 *scb = grab_file(tmpctx, "emergency.recover");
	if (!scb) {
		plugin_err(p, "Cannot read emergency.recover: %s", strerror(errno));
	} else {
		/* grab_file adds nul term */
		tal_resize(&scb, tal_bytelen(scb) - 1);
	}
	return scb;
}

/* Returns decrypted SCB in form of a u8 array */
static u8 *decrypt_scb(struct plugin *p)
{
	u8 *filedata = get_file_data(p);

	crypto_secretstream_xchacha20poly1305_state crypto_state;

	if (tal_bytelen(filedata) < ABYTES +
			 HEADER_LEN)
		plugin_err(p, "SCB file is corrupted!");

	u8 *decrypt_scb = tal_arr(tmpctx, u8, tal_bytelen(filedata) -
                          ABYTES -
                          HEADER_LEN);

	/* The header part */
	if (crypto_secretstream_xchacha20poly1305_init_pull(&crypto_state,
							    filedata,
							    (&secret)->data) != 0)
	{
		plugin_err(p, "SCB file is corrupted!");
	}

	if (crypto_secretstream_xchacha20poly1305_pull(&crypto_state, decrypt_scb,
						       NULL, 0,
						       filedata +
						       HEADER_LEN,
						       tal_bytelen(filedata)-
						       HEADER_LEN,
						       NULL, 0) != 0) {
		plugin_err(p, "SCB file is corrupted!");
	}
	return decrypt_scb;
}

static struct command_result *after_recover_rpc(struct command *cmd,
					        const char *buf,
					        const jsmntok_t *params,
					        void *cb_arg UNUSED)
{

	size_t i;
	const jsmntok_t *t;
	struct json_stream *response;

	response = jsonrpc_stream_success(cmd);

	json_for_each_obj(i, t, params)
		json_add_tok(response, json_strdup(tmpctx, buf, t), t+1, buf);

	return command_finished(cmd, response);
}

/* Recovers the channels by making RPC to `recoverchannel` */
static struct command_result *json_emergencyrecover(struct command *cmd,
				      const char *buf,
                                      const jsmntok_t *params)
{
	struct out_req *req;
	u64 version;
	u32 timestamp;
	struct scb_chan **scb;

	if (!param(cmd, buf, params, NULL))
		return command_param_failed();

	u8 *res = decrypt_scb(cmd->plugin);

	if (!fromwire_static_chan_backup(cmd,
                                         res,
                                         &version,
                                         &timestamp,
                                         &scb)) {
		plugin_err(cmd->plugin, "Corrupted SCB!");
	}

	if (version != VERSION) {
		plugin_err(cmd->plugin,
                           "Incompatible SCB file version on disk, contact the admin!");
	}

	req = jsonrpc_request_start(cmd->plugin, cmd, "recoverchannel",
				after_recover_rpc,
				&forward_error, NULL);

	json_array_start(req->js, "scb");
	for (size_t i=0; i<tal_count(scb); i++) {
		u8 *scb_hex = tal_arr(cmd, u8, 0);
		towire_scb_chan(&scb_hex,scb[i]);
		json_add_hex(req->js, NULL, scb_hex, tal_bytelen(scb_hex));
	}
	json_array_end(req->js);

	return send_outreq(cmd->plugin, req);
}

static void update_scb(struct plugin *p, struct scb_chan **channels)
{

	/* If the temp file existed before, remove it */
	unlink_noerr("scb.tmp");

	int fd = open("scb.tmp", O_CREAT|O_EXCL|O_WRONLY, 0400);
	if (fd<0)
		plugin_err(p, "Opening: %s", strerror(errno));

	plugin_log(p, LOG_DBG, "Updating the SCB file...");

	write_scb(p, fd, channels);

	/* fsync (mostly!) ensures that the file has reached the disk. */
	if (fsync(fd) != 0) {
		unlink_noerr("scb.tmp");
	}

	/* This should never fail if fsync succeeded.  But paranoia good, and
	 * bugs exist. */
	if (close(fd) != 0) {
		unlink_noerr("scb.tmp");
	}
	/* We actually need to sync the *directory itself* to make sure the
	 * file exists!  You're only allowed to open directories read-only in
	 * modern Unix though. */
	fd = open(".", O_RDONLY);
	if (fd < 0) {
		plugin_log(p, LOG_DBG, "Opening: %s", strerror(errno));
	}
	if (fsync(fd) != 0) {
		unlink_noerr("scb.tmp");
	}
	close(fd);

	/* This will atomically replace the main file */
	rename("scb.tmp", FILENAME);
}


static struct command_result
*after_send_their_peer_strg(struct command *cmd,
                            const char *buf,
                            const jsmntok_t *params,
                            void *cb_arg UNUSED)
{
        plugin_log(cmd->plugin, LOG_DBG, "Sent their peer storage!");
	return notification_handled(cmd);
}

static struct command_result
*after_send_their_peer_strg_nb(struct command *cmd,
                            const char *buf,
                            const jsmntok_t *params,
                            void *cb_arg UNUSED)
{
        plugin_log(cmd->plugin, LOG_DBG, "Unable to send Peer storage!");
	return notification_handled(cmd);
}

static struct command_result *after_listdatastore(struct command *cmd,
                                                  const char *buf,
                                                  const jsmntok_t *params,
                                                  struct node_id *nodeid)
{
        const jsmntok_t *datastoretok = json_get_member(buf,
                                                        params,
                                                        "datastore");

        if (datastoretok->size == 0)
        	return notification_handled(cmd);

        const jsmntok_t *payloadtok = json_get_member(buf,
                                                      json_get_arr(datastoretok,
                                                                   0),
                                                      "hex");
        struct out_req *req;

        u8 *hexdata = tal_hexdata(cmd,
                                  json_strdup(cmd, buf, payloadtok),
                                  payloadtok->end - payloadtok->start),
        *payload = towire_your_peer_storage(cmd, hexdata);

        plugin_log(cmd->plugin, LOG_DBG,
                   "sending their backup from our datastore");

        req = jsonrpc_request_start(cmd->plugin,
                                    cmd,
                                    "sendcustommsg",
                                    after_send_their_peer_strg,
                                    after_send_their_peer_strg_nb,
                                    NULL);

        json_add_node_id(req->js, "node_id", nodeid);
        json_add_hex(req->js, "msg", payload,
                     tal_bytelen(payload));

        return send_outreq(cmd->plugin, req);
}

static struct command_result *after_send_scb(struct command *cmd,
                                             const char *buf,
                                             const jsmntok_t *params,
                                             struct node_id *nodeid)
{
        plugin_log(cmd->plugin, LOG_DBG, "Peer storage sent!");
        struct out_req *req;
        req = jsonrpc_request_start(cmd->plugin,
                                    cmd,
                                    "listdatastore",
                                    after_listdatastore,
                                    &forward_error,
                                    nodeid);
        json_add_node_id(req->js,"key",nodeid);
        return send_outreq(cmd->plugin, req);
}

struct info {
	size_t idx;
};

static struct command_result *after_send_scb_single(struct command *cmd,
                                             const char *buf,
                                             const jsmntok_t *params,
                                             struct info *info)
{
        plugin_log(cmd->plugin, LOG_INFORM, "Peer storage sent!");
	if (--info->idx != 0)
		return command_still_pending(cmd);

	return notification_handled(cmd);
}

static struct command_result *after_listpeers(struct command *cmd,
                                             const char *buf,
                                             const jsmntok_t *params,
                                             void *cb_arg UNUSED)
{
	const jsmntok_t *peers, *peer, *nodeid;
        struct out_req *req;
	size_t i;
	struct info *info = tal(cmd, struct info);
	struct node_id *node_id = tal(cmd, struct node_id);
	bool is_connected;

	u8 *scb = get_file_data(cmd->plugin);

        u8 *serialise_scb = towire_peer_storage(cmd, scb);

	peers = json_get_member(buf, params, "peers");

	info->idx = 0;
	json_for_each_arr(i, peer, peers) {
		json_to_bool(buf, json_get_member(buf, peer, "connected"),
				&is_connected);

		if (is_connected) {
			nodeid = json_get_member(buf, peer, "id");
			json_to_node_id(buf, nodeid, node_id);

			req = jsonrpc_request_start(cmd->plugin,
				cmd,
				"sendcustommsg",
				after_send_scb_single,
				&forward_error,
				info);

			json_add_node_id(req->js, "node_id", node_id);
			json_add_hex(req->js, "msg", serialise_scb,
				tal_bytelen(serialise_scb));
			info->idx++;
			send_outreq(cmd->plugin, req);
		}
	}

	if (info->idx == 0)
		return notification_handled(cmd);
	return command_still_pending(cmd);
}

static struct command_result *after_staticbackup(struct command *cmd,
					         const char *buf,
					         const jsmntok_t *params,
					         void *cb_arg UNUSED)
{
	struct scb_chan **scb_chan;
	const jsmntok_t *scbs = json_get_member(buf, params, "scb");
	struct out_req *req;
	json_to_scb_chan(buf, scbs, &scb_chan);
	plugin_log(cmd->plugin, LOG_INFORM, "Updating the SCB");

	update_scb(cmd->plugin, scb_chan);
	struct info *info = tal(cmd, struct info);
	info->idx = 0;
	req = jsonrpc_request_start(cmd->plugin,
                                    cmd,
                                    "listpeers",
                                    after_listpeers,
                                    &forward_error,
                                    info);
	return send_outreq(cmd->plugin, req);
}

static struct command_result *json_state_changed(struct command *cmd,
					         const char *buf,
					         const jsmntok_t *params)
{
	const jsmntok_t *notiftok = json_get_member(buf,
                                                    params,
                                                    "channel_state_changed"),
	*statetok = json_get_member(buf, notiftok, "new_state");

	if (json_tok_streq(buf, statetok, "CLOSED") ||
		json_tok_streq(buf, statetok, "CHANNELD_AWAITING_LOCKIN") ||
		json_tok_streq(buf, statetok, "DUALOPENED_AWAITING_LOCKIN")) {
		struct out_req *req;
		req = jsonrpc_request_start(cmd->plugin,
                                            cmd,
                                            "staticbackup",
                                            after_staticbackup,
                                            &forward_error,
                                            NULL);

		return send_outreq(cmd->plugin, req);
	}

	return notification_handled(cmd);
}


static struct command_result *json_connect(struct command *cmd,
                                           const char *buf,
                                           const jsmntok_t *params)
{
	const jsmntok_t *nodeid = json_get_member(buf,
                                                  params,
                                                  "id");

        struct node_id *node_id = tal(cmd, struct node_id);
        json_to_node_id(buf, nodeid, node_id);
	struct out_req *req;
	u8 *scb = get_file_data(cmd->plugin);
        u8 *serialise_scb = towire_peer_storage(cmd, scb);

        req = jsonrpc_request_start(cmd->plugin,
                                    cmd,
                                    "sendcustommsg",
                                    after_send_scb,
                                    &forward_error,
                                    node_id);

        json_add_node_id(req->js, "node_id", node_id);
        json_add_hex(req->js, "msg", serialise_scb,
                     tal_bytelen(serialise_scb));

        return send_outreq(cmd->plugin, req);
}

static struct command_result *after_datastore(struct command *cmd,
                                             const char *buf,
                                             const jsmntok_t *params,
                                             void *cb_arg UNUSED)
{
        return command_hook_success(cmd);
}

static struct command_result *failed_peer_restore(struct command *cmd,
						  struct node_id *node_id,
						  char *reason)
{
	plugin_log(cmd->plugin, LOG_DBG, "PeerStorageFailed!: %s: %s",
		   type_to_string(tmpctx, struct node_id, node_id),
		   reason);
	return command_hook_success(cmd);
}

static struct command_result *handle_your_peer_storage(struct command *cmd,
					         const char *buf,
					         const jsmntok_t *params)
{
        struct node_id node_id;
        u8 *payload, *payload_deserialise;
        struct out_req *req;
	const char *err = json_scan(cmd, buf, params,
				    "{payload:%,peer_id:%}",
				    JSON_SCAN_TAL(cmd,
				    		  json_tok_bin_from_hex,
				    		  &payload),
				    JSON_SCAN(json_to_node_id,
				    	      &node_id));
	if (err) {
		plugin_err(cmd->plugin,
			   "`your_peer_storage` response did not scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));
	}

	if (fromwire_peer_storage(cmd, payload, &payload_deserialise)) {
		req = jsonrpc_request_start(cmd->plugin,
                                    cmd,
                                    "datastore",
                                    after_datastore,
                                    &forward_error,
                                    NULL);

		json_array_start(req->js, "key");
		json_add_node_id(req->js, NULL, &node_id);
		json_add_string(req->js, NULL, "chanbackup");
		json_array_end(req->js);
		json_add_hex(req->js, "hex", payload_deserialise,
			tal_bytelen(payload_deserialise));
		json_add_string(req->js, "mode", "create-or-replace");

		return send_outreq(cmd->plugin, req);
	} else if (fromwire_your_peer_storage(cmd, payload, &payload_deserialise)) {
		plugin_log(cmd->plugin, LOG_DBG,
                           "Received peer_storage from peer.");

        	crypto_secretstream_xchacha20poly1305_state crypto_state;

                if (tal_bytelen(payload_deserialise) < ABYTES +
			                               HEADER_LEN)
		        return failed_peer_restore(cmd, &node_id,
						   "Too short!");

                u8 *decoded_bkp = tal_arr(tmpctx, u8,
				        tal_bytelen(payload_deserialise) -
                                	ABYTES -
                                	HEADER_LEN);

                /* The header part */
                if (crypto_secretstream_xchacha20poly1305_init_pull(&crypto_state,
                                                                    payload_deserialise,
                                                                    (&secret)->data) != 0)
                        return failed_peer_restore(cmd, &node_id,
						   "Peer altered our data");

                if (crypto_secretstream_xchacha20poly1305_pull(&crypto_state,
                                                               decoded_bkp,
                                                               NULL, 0,
                                                               payload_deserialise +
                                                               HEADER_LEN,
                                                               tal_bytelen(payload_deserialise) -
                                                               HEADER_LEN,
                                                               NULL, 0) != 0)
                        return failed_peer_restore(cmd, &node_id,
					           "Peer altered our data");


                req = jsonrpc_request_start(cmd->plugin,
                                    cmd,
                                    "datastore",
                                    after_datastore,
                                    &forward_error,
                                    NULL);

                json_array_start(req->js, "key");
                json_add_string(req->js, NULL, "latestbkp");
                json_array_end(req->js);
                json_add_hex(req->js, "hex", decoded_bkp,
                             tal_bytelen(decoded_bkp));
                json_add_string(req->js, "mode", "create-or-replace");

                return send_outreq(cmd->plugin, req);
	} else {
                        plugin_log(cmd->plugin, LOG_BROKEN,
                                   "Peer sent bad custom message for chanbackup!");
                        return command_hook_success(cmd);
        }
}

static struct command_result *after_latestbkp(struct command *cmd,
					        const char *buf,
					        const jsmntok_t *params,
					        void *cb_arg UNUSED)
{
        u64 version;
	u32 timestamp;
	struct scb_chan **scb;
        struct json_stream *response;
        const jsmntok_t *datastoretok = json_get_member(buf,
                                                        params,
                                                        "datastore");
        struct out_req *req;

        if (datastoretok->size == 0) {
        	response = jsonrpc_stream_success(cmd);

		json_add_string(response, "result",
				"No backup received from peers");
		return command_finished(cmd, response);
        }

        const jsmntok_t *bkp = json_get_member(buf,
                                               json_get_arr(datastoretok, 0),
                                               "hex");

        u8 *res = tal_hexdata(cmd,
                              json_strdup(cmd, buf, bkp),
                              bkp->end - bkp->start);
	if (!fromwire_static_chan_backup(cmd,
                                         res,
                                         &version,
                                         &timestamp,
                                         &scb)) {
		plugin_err(cmd->plugin, "Corrupted SCB on disk!");
	}

	if (version != VERSION) {
		plugin_err(cmd->plugin,
                           "Incompatible version, Contact the admin!");
	}

        req = jsonrpc_request_start(cmd->plugin, cmd, "recoverchannel",
				after_recover_rpc,
				&forward_error, NULL);

	json_array_start(req->js, "scb");
	for (size_t i=0; i<tal_count(scb); i++) {
		u8 *scb_hex = tal_arr(cmd, u8, 0);
		towire_scb_chan(&scb_hex,scb[i]);
		json_add_hex(req->js, NULL, scb_hex, tal_bytelen(scb_hex));
	}
	json_array_end(req->js);

	return send_outreq(cmd->plugin, req);

}

static struct command_result *json_restorefrompeer(struct command *cmd,
				      const char *buf,
                                      const jsmntok_t *params)
{
	struct out_req *req;

	if (!param(cmd, buf, params, NULL))
		return command_param_failed();

        req = jsonrpc_request_start(cmd->plugin,
                                    cmd,
                                    "listdatastore",
                                    after_latestbkp,
                                    &forward_error,
                                    NULL);
        json_add_string(req->js, "key", "latestbkp");

	return send_outreq(cmd->plugin, req);
}

static const char *init(struct plugin *p,
			const char *buf UNUSED,
			const jsmntok_t *config UNUSED)
{
	struct scb_chan **scb_chan;
	const char *info = "scb secret";
	u8 *info_hex = tal_dup_arr(tmpctx, u8, (u8*)info, strlen(info), 0);

	rpc_scan(p, "staticbackup",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{scb:%}", JSON_SCAN(json_to_scb_chan, &scb_chan));

	rpc_scan(p, "makesecret",
		 take(json_out_obj(NULL, "hex",
		 		   tal_hexstr(tmpctx,
				   	      info_hex,
					      tal_bytelen(info_hex)))),
		 "{secret:%}", JSON_SCAN(json_to_secret, &secret));

	plugin_log(p, LOG_DBG, "Chanbackup Initialised!");

	/* flush the tmp file, if exists */
	unlink_noerr("scb.tmp");

	maybe_create_new_scb(p, scb_chan);

	return NULL;
}

static const struct plugin_notification notifs[] = {
	{
		"channel_state_changed",
		json_state_changed,
	},
	{
		"connect",
		json_connect,
	},
};

static const struct plugin_hook hooks[] = {
        {
                "custommsg",
                handle_your_peer_storage,
        },
};

static const struct plugin_command commands[] = { {
		"emergencyrecover",
		"recovery",
		"Populates the DB with stub channels",
		"returns stub channel-id's on completion",
		json_emergencyrecover,
	},
        {
                "restorefrompeer",
                "recovery",
                "Checks if i have got a backup from a peer, and if so, will stub "
		"those channels in the database and if is successful, will return "
		"list of channels that have been successfully stubbed",
                "return channel-id's on completion",
                json_restorefrompeer,
        },
};

int main(int argc, char *argv[])
{
        setup_locale();
	struct feature_set *features = feature_set_for_feature(NULL, PEER_STORAGE_FEATURE);
	feature_set_or(features,
		       take(feature_set_for_feature(NULL,
						    YOUR_PEER_STORAGE_FEATURE)));

	plugin_main(argv, init, PLUGIN_STATIC, true, features,
		    commands, ARRAY_SIZE(commands),
	            notifs, ARRAY_SIZE(notifs), hooks, ARRAY_SIZE(hooks),
		    NULL, 0,  /* Notification topics we publish */
		    NULL);
}
