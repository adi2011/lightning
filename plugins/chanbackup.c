#include "config.h"
#include <ccan/array_size/array_size.h>
#include <common/json_tok.h>
#include <common/json.h>
#include <common/json_stream.h>
#include <ccan/tal/str/str.h>
#include <plugins/libplugin.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/noerr/noerr.h>
#include <errno.h>
#include <fcntl.h>
#include <ccan/json_out/json_out.h>
#include <ccan/cast/cast.h>
#include <ccan/json_out/json_out.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <plugins/libplugin.h>
#include <common/type_to_string.h>
#include <unistd.h>
#include <sodium.h>
#include <common/hsm_encryption.h>

#include <ccan/err/err.h>
#include <ccan/fdpass/fdpass.h>

/* Global secret object to keep the derived encryption key for the SCB */
struct secret secret;

/* Helper to fetch out SCB from the RPC call */
static bool json_to_str(const char *buffer, const jsmntok_t *tok,
			const char **t)
{
	*t = json_strdup(tmpctx, buffer, tok);
	return true;
}

/* This writes encrypted scb in the file */
static void write_hsm(struct plugin *p, int fd, const jsmntok_t *scb_arr, 
						const char *buf){

	int i = 0;
	const jsmntok_t *t;
	char *data = tal(scb_arr, char);
	
	plugin_log(p,LOG_DBG, "buf is -----------------------------%s------------------------------------------", buf);

	json_for_each_arr(i,t,scb_arr){
		char *c = json_strdup(tmpctx, buf, json_get_arr(scb_arr, i));
		
		strcat(c, ",");

		data = tal_strcat(scb_arr, data, c);
	}
	plugin_log(p,LOG_DBG, "data is -----------------------------%s------------------------------------------", data);
	u8 *point = tal_dup_arr(scb_arr, u8, (u8 *)data, strlen(data), 0);
	u8 *final = tal_arr(scb_arr, 
						u8, 
						tal_bytelen(point) + 
							crypto_secretstream_xchacha20poly1305_ABYTES + 
							crypto_secretstream_xchacha20poly1305_HEADERBYTES
						);

	crypto_secretstream_xchacha20poly1305_state crypto_state;

	if (crypto_secretstream_xchacha20poly1305_init_push(&crypto_state, final,
								(&secret)->data) != 0)
		return;
	
	if (crypto_secretstream_xchacha20poly1305_push(
							   &crypto_state,
						       final + crypto_secretstream_xchacha20poly1305_HEADERBYTES,
						       NULL, point,
						       tal_bytelen(point),
						       /* Additional data and tag */
						       NULL, 0, 0))
		return;
	
	if (!write_all(fd, final, tal_bytelen(final))) {
			unlink_noerr("scb");
	}
}

/* checks if the SCB file exists, creates a new one in case it doesn't. */
static void maybe_create_new_scb(struct plugin *p, const char *scb_buf)
{

	/*~ Note that this is opened for write-only, even though the permissions
	 * are set to read-only.  That's perfectly valid! */
	int fd = open("scb", O_CREAT|O_EXCL|O_WRONLY, 0400);
	if (fd < 0) {
		/* If this is not the first time we've run, it will exist. */
		if (errno == EEXIST)
			return;
	}

	jsmntok_t *scb_arr = json_parse_simple(tmpctx, scb_buf, strlen(scb_buf));
	plugin_log(p, LOG_DBG, "here");
	
	write_hsm(p, fd, scb_arr, scb_buf);

	plugin_log(p, LOG_DBG, "here!");

	/*~ fsync (mostly!) ensures that the file has reached the disk. */
	if (fsync(fd) != 0) {
		unlink_noerr("scb");
	}

	/*~ This should never fail if fsync succeeded.  But paranoia good, and
	 * bugs exist. */
	if (close(fd) != 0) {
		unlink_noerr("scb");
	}
	/*~ We actually need to sync the *directory itself* to make sure the
	 * file exists!  You're only allowed to open directories read-only in
	 * modern Unix though. */
	fd = open(".", O_RDONLY);
	if (fd < 0) {
		}
	if (fsync(fd) != 0) {
		unlink_noerr("scb");
		}
	close(fd);
}


/* Returns decrypted SCB in form of a u8 array */
static u8 *decrypt_scb(struct plugin *p){
	struct stat st;
	int fd = open("scb", O_RDONLY);

	if (stat("scb", &st) != 0){
		plugin_log(p, LOG_DBG, "SCB file is corrupted!: %s", strerror(errno));
		return NULL;	
	}

	u8 final[st.st_size];

	if (!read_all(fd, &final, st.st_size)){
		plugin_log(p, LOG_DBG, "SCB file is corrupted!: %s", strerror(errno));
		return NULL;
	}
	

	// plugin_log(p, LOG_DBG, "%s ------------------------------------------------------", tal_hexstr(tmpctx, final, st.st_size));

	crypto_secretstream_xchacha20poly1305_state crypto_state;
	u8 *ans = tal_arr(tmpctx, u8, st.st_size - crypto_secretstream_xchacha20poly1305_ABYTES);
	/* The header part */
	if (crypto_secretstream_xchacha20poly1305_init_pull(&crypto_state, final,
							    (&secret)->data) != 0)
		return 0;
	// plugin_log(p, LOG_DBG, "string ------------------------------------------------------------ decrypt");

	if (crypto_secretstream_xchacha20poly1305_pull(&crypto_state, ans,
						       NULL, 0,
						       final + crypto_secretstream_xchacha20poly1305_HEADERBYTES,
						       st.st_size - crypto_secretstream_xchacha20poly1305_HEADERBYTES,
						       NULL, 0) != 0)
		return 0;
	
	close(fd);

	return ans;
}

static struct command_result *testrpc_cb(struct command *cmd,
					 const char *buf,
					 const jsmntok_t *params,
					 void *cb_arg UNUSED)
{

	struct json_stream *response;
	
	response = jsonrpc_stream_success(cmd);

	json_add_string(response, "Status", "Successfully recovered the channel, Wait for fund-sweep..");
	return command_finished(cmd, response);
}


/* Recovers the channels by making RPC to `emergencystubchannel` */
static struct command_result *recover(struct command *cmd,
					      const char *buf,
					      const jsmntok_t *params)
{
	if (!param(cmd, buf, params, NULL))
		return command_param_failed();
	struct out_req *req;
	char *res = (char *)decrypt_scb(cmd->plugin);


	req = jsonrpc_request_start(cmd->plugin, cmd, "emergencystubchannel",
				    testrpc_cb,
				    testrpc_cb, NULL);

	json_add_string(req->js, "scb", res);
	return send_outreq(cmd->plugin, req);
}


static struct command_result *after_hexscb(struct command *cmd,
					 const char *buf,
					 const jsmntok_t *params,
					 void *cb_arg UNUSED)
{

	const char *scb_buf =  json_strdup(tmpctx, buf, params);
	const jsmntok_t *scb_arr = json_parse_simple(tmpctx, scb_buf, strlen(scb_buf)),
					*scbs = json_get_member(scb_buf, scb_arr, "scb");

	maybe_create_new_scb(cmd->plugin, json_strdup(tmpctx, scb_buf, scbs));
	return notification_handled(cmd);
	
}


static struct command_result *json_chanopen(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *params)
{

	plugin_log(cmd->plugin, LOG_INFORM, "New channel opened, Updating the SCB");
	unlink_noerr("scb");
	struct out_req *req;
	req = jsonrpc_request_start(cmd->plugin, cmd ,"hex-scb",
						 after_hexscb, after_hexscb, 
						NULL);

	return send_outreq(cmd->plugin, req);
}

static struct command_result *json_state_changed(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *params)
{

	const jsmntok_t *statetok = json_get_member(buf, params, "new_state");

	unlink_noerr("scb");
	const char *state = json_strdup(tmpctx, buf, statetok);

	if(strcmp(state ,"CLOSED") == 0){
		plugin_log(cmd->plugin, LOG_INFORM, "Channel closed: Updating the SCB");
		struct out_req *req;
		req = jsonrpc_request_start(cmd->plugin, cmd ,"hex-scb",
							after_hexscb, after_hexscb, 
							NULL);

		return send_outreq(cmd->plugin, req);
	}

	return notification_handled(cmd);
}

static const char *init(struct plugin *p,
			const char *buf UNUSED,
			const jsmntok_t *config UNUSED)
{

	const char *scb_buf;
	rpc_scan(p, "hex-scb",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{scb:%}", JSON_SCAN(json_to_str, &scb_buf));
	
	rpc_scan(p, "getsecret",
		 take(json_out_obj(NULL, "info", "scb secret")),
		 "{Secret_Key:%}", JSON_SCAN(json_to_secret, &secret));

	plugin_log(p, LOG_DBG, "Chanbackup Initialised!");
	maybe_create_new_scb(p, scb_buf);

	return NULL;
}


static const struct plugin_notification notifs[] = { 
	{
		"channel_opened",
		json_chanopen,
	}, 
	{
		"channel_state_changed",
		json_state_changed,
	}
};

static const struct plugin_command commands[] = { {
		"scbrecover",
		"recovery",
		"Populates the DB with stub channels",
		"returns success on completion",
		recover,
	}
};

int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, PLUGIN_RESTARTABLE, true, NULL,
		    commands, ARRAY_SIZE(commands),
	        notifs, ARRAY_SIZE(notifs), NULL, 0,
		    NULL, 0,  /* Notification topics we publish */
		    NULL);
}