#include "config.h"
#include <ccan/array_size/array_size.h>
#include <common/features.h>
#include <common/gossmap.h>
#include <common/hsm_encryption.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/type_to_string.h>
#include <errno.h>
#include <plugins/libplugin.h>
#include <unistd.h>

static struct plugin *plugin;
static struct gossmap *global_gossmap;
static struct plugin_timer *lost_state_timer, *find_exes_timer, *peer_storage_timer;
/* This tells if we are already in the process of recovery. */
static bool recovery, already_has_peers;
static void do_check_lost_peer (void *unused);
static void do_check_gossip (void *unused);
static void do_find_peer_storage (void *unused);
static struct node_id local_id;

/* List of most connected nodes on the network */
static const char *nodes_for_gossip[] = {
	// "02312627fdf07fbdd7e5ddb136611bdde9b00d26821d14d94891395452f67af248@23.237.77.12:9735",

	// "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f@3.33.236.230:9735", //ACINQ
	// "035e4ff418fc8b5554c5d9eea66396c227bd429a3251c8cbc711002ba215bfc226@170.75.163.209:9735", //WalletOfSatoshi
	// "0217890e3aad8d35bc054f43acc00084b25229ecff0ab68debd82883ad65ee8266@23.237.77.11:9735", //1ML.com node ALPHA
	// "0242a4ae0c5bef18048fbecf995094b74bfb0f7391418d71ed394784373f41e4f3@3.124.63.44:9735", //CoinGate
	// "0364913d18a19c671bb36dd04d6ad5be0fe8f2894314c36a9db3f03c2d414907e1@192.243.215.102:9735", //LQwD-Canada
	// "02f1a8c87607f415c8f22c00593002775941dea48869ce23096af27b0cfdcc0b69@52.13.118.208:9735", //Kraken ≡ƒÉÖΓÜí
	// "03cde60a6323f7122d5178255766e38114b4722ede08f7c9e0c5df9b912cc201d6@34.65.85.39:9745", //bfx-lnd1
	// "024b9a1fa8e006f1e3937f65f66c408e6da8e1ca728ea43222a7381df1cc449605@165.232.168.69:9735", //BLUEIRON-v23.08.1
	// "034ea80f8b148c750463546bd999bf7321a0e6dfc60aaf84bd0400a2e8d376c0d5@213.174.156.66:9735", //LNBiG Hub-1
	// "026165850492521f4ac8abd9bd8088123446d126f648ca35e60f88177dc149ceb2@45.86.229.190:9735", //Boltz
};


static struct command_result *connect_success(struct command *cmd,
					      const char *buf,
					      const jsmntok_t *params,
					      size_t *index)
{
        plugin_log(plugin, LOG_DBG, "Connected to %s", nodes_for_gossip[*index]);
	return command_still_pending(cmd);
}

static struct command_result *connect_fail(struct command *cmd,
					   const char *buf,
					   const jsmntok_t *params,
					   size_t *index)
{
        plugin_log(plugin, LOG_DBG, "Failed to connect to %s!", nodes_for_gossip[*index]);
	return command_still_pending(cmd);
}

static struct command_result *after_emergency_recover(struct command *cmd,
					   	      const char *buf,
					   	      const jsmntok_t *params,
					   	      void *cb_arg UNUSED)
{
	/* TODO: CREATE GOSSMAP, connect to old peers and fetch peer storage */
	plugin_log(plugin, LOG_DBG, "emergency_recovery called");
	return command_still_pending(cmd);
}

static void find_peer_storage (void *unused) {

	plugin_log(plugin, LOG_DBG, "CHECKING peer storage+++====================================== %s", type_to_string(tmpctx, struct node_id, &local_id));
	peer_storage_timer = plugin_timer(plugin, time_from_sec(1), do_find_peer_storage, NULL);
	return;
}


static void do_find_peer_storage (void *unused) {
	peer_storage_timer = NULL;
	plugin_log(plugin, LOG_DBG, "CHECKING peer storage++====================================== %s", type_to_string(tmpctx, struct node_id, &local_id));
	find_peer_storage(NULL);
	return;
}

static void do_check_gossip (void *unused) {
	find_exes_timer = NULL;

	gossmap_refresh(global_gossmap, NULL);

	plugin_log(plugin, LOG_DBG, "CHECKING GOSSIP++====================================== %s", type_to_string(tmpctx, struct node_id, &local_id));

	struct gossmap_node *n = gossmap_find_node(global_gossmap, &local_id);

	if (n) {
		plugin_log(plugin, LOG_DBG, "Found node !============================!");
		for (struct gossmap_chan *c = gossmap_first_chan(global_gossmap);
	     		c;
	     		c = gossmap_next_chan(global_gossmap, c)) {
				struct gossmap_node *x = gossmap_node_byidx(global_gossmap, c->half[1].nodeidx);
				struct gossmap_node *y = gossmap_node_byidx(global_gossmap, c->half[0].nodeidx);
				struct node_id a, b;
				gossmap_node_get_id(global_gossmap, x, &a);
				gossmap_node_get_id(global_gossmap, y, &b);

				struct out_req *req;

				if (!node_id_cmp(&a, &local_id)) {
					req = jsonrpc_request_start(plugin,
								    NULL,
								    "connect",
								    &forward_result,
								    &forward_error,
								    NULL);
					json_add_node_id(req->js, "id", &b);
					plugin_log(plugin, LOG_DBG, "Connecting to: %s", type_to_string(tmpctx, struct node_id, &b));
					send_outreq(plugin, req);
				} else if (!node_id_cmp(&b, &local_id)) {

					req = jsonrpc_request_start(plugin,
								    NULL,
								    "connect",
								    &forward_result,
								    &forward_error,
								    NULL);
					json_add_node_id(req->js, "id", &a);
					plugin_log(plugin, LOG_DBG, "Connecting to: %s", type_to_string(tmpctx, struct node_id, &a));
					send_outreq(plugin, req);
				}
		}
		do_find_peer_storage(NULL);
		return;
	}

	find_exes_timer = plugin_timer(plugin, time_from_sec(5), do_check_gossip, NULL);
	return;
}

static void entering_recovery_mode(void *unused) {
	if(!already_has_peers) {
		for (size_t i = 0; i < ARRAY_SIZE(nodes_for_gossip); i++) {
			struct out_req *req;
			req = jsonrpc_request_start(plugin,
						    NULL,
						    "connect",
						    connect_success,
						    connect_fail,
						    &i);
			json_add_string(req->js, "id", nodes_for_gossip[i]);
			send_outreq(plugin, req);
		}
	}

	struct out_req *req_emer_recovery;

	/* Let's try to recover whatever we have in the emergencyrecover file. */
	req_emer_recovery = jsonrpc_request_start(plugin,
						  NULL,
						  "emergencyrecover",
						  after_emergency_recover,
						  &forward_error,
						  NULL);

	send_outreq(plugin, req_emer_recovery);
	find_exes_timer = plugin_timer(plugin, time_from_sec(5), do_check_gossip, NULL);
	return;
}

static struct command_result *after_listpeerchannels(struct command *cmd,
					             const char *buf,
					             const jsmntok_t *params,
					             void *cb_arg UNUSED)
{
	plugin_log(plugin, LOG_DBG, "Listpeerchannels called");
	struct listpeers_channel **channels = json_to_listpeers_channels(tmpctx, buf, params);
	for (size_t i=0; i<tal_count(channels); i++) {
		struct listpeers_channel *chan = channels[i];
		if (chan->lost_state) {
			plugin_log(plugin, LOG_DBG, "Detected a channel with lost state, Entering Recovery mode!");
			recovery = true;
			break;
		}
	}

	// TODO: Remove this--
	recovery = true;

	if (recovery) {
		entering_recovery_mode(NULL);
		return command_still_pending(NULL);
	}

	lost_state_timer = plugin_timer(plugin, time_from_sec(2), do_check_lost_peer, NULL);
	return timer_complete(plugin);
}

static struct command_result *check_lost_peer(void *unused) {
	struct out_req *req;
	req = jsonrpc_request_start(plugin, NULL, "listpeerchannels",
					after_listpeerchannels,
					&forward_error, NULL);

	return send_outreq(plugin, req);
}

static void do_check_lost_peer (void *unused)
{

	/* Set to NULL when already in progress. */
	lost_state_timer = NULL;

	if (recovery) {
		return;
	}

	check_lost_peer(unused);
}

static const char *init(struct plugin *p,
			const char *buf UNUSED,
			const jsmntok_t *config UNUSED)
{
	plugin = p;
	plugin_log(p, LOG_DBG, "Recover Plugin Initialised!");
	recovery = false;
	lost_state_timer = plugin_timer(plugin, time_from_sec(2), do_check_lost_peer, NULL);
	u32 num_peers;
	size_t num_cupdates_rejected;

	/* Find number of peers */
	rpc_scan(p, "getinfo",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{id:%,num_peers:%}",
		 JSON_SCAN(json_to_node_id, &local_id),
		 JSON_SCAN(json_to_u32, &num_peers));

	global_gossmap = gossmap_load(NULL,
				      GOSSIP_STORE_FILENAME,
				      &num_cupdates_rejected);

	if (!global_gossmap)
		plugin_err(p, "Could not load gossmap %s: %s",
			   GOSSIP_STORE_FILENAME, strerror(errno));

	if (num_cupdates_rejected)
		plugin_log(p, LOG_DBG,
			   "gossmap ignored %zu channel updates",
			   num_cupdates_rejected);

	plugin_log(p, LOG_DBG, "Gossmap loaded!");

	already_has_peers = num_peers > 2 ? 1: 0;

	return NULL;
}


int main(int argc, char *argv[])
{
        setup_locale();

	plugin_main(argv, init, PLUGIN_STATIC, true, NULL,
		    NULL, 0,
		    NULL, 0, NULL, 0,
		    NULL, 0,  /* Notification topics we publish */
		    NULL);
}

