/*~ Welcome to the hsm daemon: keeper of our secrets!
 *
 * This is a separate daemon which keeps a root secret from which all others
 * are generated.  It starts with one client: lightningd, which can ask for
 * new sockets for other clients.  Each client has a simple capability map
 * which indicates what it's allowed to ask for.  We're entirely driven
 * by request, response.
 */
#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/intmap/intmap.h>
#include <ccan/io/fdpass/fdpass.h>
#include <ccan/noerr/noerr.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/str/str.h>
#include <common/daemon_conn.h>
#include <common/hsm_encryption.h>
#include <common/memleak.h>
#include <common/status.h>
#include <common/status_wiregen.h>
#include <common/subdaemon.h>
#include <common/type_to_string.h>
#include <errno.h>
#include <fcntl.h>
#include <hsmd/capabilities.h>
/*~ _wiregen files are autogenerated by tools/generate-wire.py */
#include <hsmd/libhsmd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <wire/wire_io.h>

/*~ Each subdaemon is started with stdin connected to lightningd (for status
 * messages), and stderr untouched (for emergency printing).  File descriptors
 * 3 and beyond are set up on other sockets: for hsmd, fd 3 is the request
 * stream from lightningd. */
#define REQ_FD 3

#if DEVELOPER
/* If they specify --dev-force-privkey it ends up in here. */
extern struct privkey *dev_force_privkey;
/* If they specify --dev-force-bip32-seed it ends up in here. */
extern struct secret *dev_force_bip32_seed;
#endif

/* Temporary storage for the secret until we pass it to `hsmd_init` */
struct secret hsm_secret;

/*~ We keep track of clients, but there's not much to keep. */
struct client {
	/* The ccan/io async io connection for this client: it closes, we die. */
	struct io_conn *conn;

	/*~ io_read_wire needs a pointer to store incoming messages until
	 * it has the complete thing; this is it. */
	u8 *msg_in;

	/*~ Useful for logging, but also used to derive the per-channel seed. */
	struct node_id id;

	/*~ This is a unique value handed to us from lightningd, used for
	 * per-channel seed generation (a single id may have multiple channels
	 * over time).
	 *
	 * It's actually zero for the initial lightningd client connection and
	 * the ones for gossipd and connectd, which don't have channels
	 * associated. */
	u64 dbid;

	/* What is this client allowed to ask for? */
	u64 capabilities;

	/* Params to apply to all transactions for this client */
	const struct chainparams *chainparams;

	/* Client context to pass over to libhsmd for its calls. */
	struct hsmd_client *hsmd_client;
};

/*~ We keep a map of nonzero dbid -> clients, mainly for leak detection.
 * This is ccan/uintmap, which maps u64 to some (non-NULL) pointer.
 * I really dislike these kinds of declaration-via-magic macro things, as
 * tags can't find them without special hacks, but the payoff here is that
 * the map is typesafe: the compiler won't let you put anything in but a
 * struct client pointer. */
static UINTMAP(struct client *) clients;
/*~ Plus the three zero-dbid clients: master, gossipd and connnectd. */
static struct client *dbid_zero_clients[3];
static size_t num_dbid_zero_clients;

/*~ We need this deep inside bad_req_fmt, and for memleak, so we make it a
 * global. */
static struct daemon_conn *status_conn;

/* This is used for various assertions and error cases. */
static bool is_lightningd(const struct client *client)
{
	return client == dbid_zero_clients[0];
}

/* Pre-declare this, due to mutual recursion */
static struct io_plan *handle_client(struct io_conn *conn, struct client *c);

/*~ ccan/compiler.h defines PRINTF_FMT as the gcc compiler hint so it will
 * check that fmt and other trailing arguments really are the correct type.
 *
 * This is a convenient helper to tell lightningd we've received a bad request
 * and closes the client connection.  This should never happen, of course, but
 * we definitely want to log if it does.
 */
static struct io_plan *bad_req_fmt(struct io_conn *conn,
				   struct client *c,
				   const u8 *msg_in,
				   const char *fmt, ...)
	PRINTF_FMT(4,5);

static struct io_plan *bad_req_fmt(struct io_conn *conn,
				   struct client *c,
				   const u8 *msg_in,
				   const char *fmt, ...)
{
	va_list ap;
	char *str;

	va_start(ap, fmt);
	str = tal_fmt(tmpctx, fmt, ap);
	va_end(ap);

	/*~ If the client was actually lightningd, it's Game Over; we actually
	 * fail in this case, and it will too. */
	if (is_lightningd(c)) {
		status_broken("%s", str);
		master_badmsg(fromwire_peektype(msg_in), msg_in);
	}

	/*~ Nobody should give us bad requests; it's a sign something is broken */
	status_broken("%s: %s", type_to_string(tmpctx, struct node_id, &c->id), str);

	/*~ Note the use of NULL as the ctx arg to towire_hsmstatus_: only
	 * use NULL as the allocation when we're about to immediately free it
	 * or hand it off with take(), as here.  That makes it clear we don't
	 * expect it to linger, and in fact our memleak detection will
	 * complain if it does (unlike using the deliberately-transient
	 * tmpctx). */
	daemon_conn_send(status_conn,
			 take(towire_hsmstatus_client_bad_request(NULL,
								  &c->id,
								  str,
								  msg_in)));

	/*~ The way ccan/io works is that you return the "plan" for what to do
	 * next (eg. io_read).  io_close() is special: it means to close the
	 * connection. */
	return io_close(conn);
}

/* Convenience wrapper for when we simply can't parse. */
static struct io_plan *bad_req(struct io_conn *conn,
			       struct client *c,
			       const u8 *msg_in)
{
	return bad_req_fmt(conn, c, msg_in, "could not parse request");
}

/*~ This plan simply says: read the next packet into 'c->msg_in' (parent 'c'),
 * and then call handle_client with argument 'c' */
static struct io_plan *client_read_next(struct io_conn *conn, struct client *c)
{
	c->msg_in = tal_free(c->msg_in);
	return io_read_wire(conn, c, &c->msg_in, handle_client, c);
}

/*~ This is the destructor on our client: we may call it manually, but
 * generally it's called because the io_conn associated with the client is
 * closed by the other end. */
static void destroy_client(struct client *c)
{
	if (!uintmap_del(&clients, c->dbid))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed to remove client dbid %"PRIu64, c->dbid);
}

static struct client *new_client(const tal_t *ctx,
				 const struct chainparams *chainparams,
				 const struct node_id *id,
				 u64 dbid,
				 const u64 capabilities,
				 int fd)
{
	struct client *c = tal(ctx, struct client);

	c->msg_in = NULL;

	/*~ All-zero pubkey is used for the initial master connection */
	if (id) {
		c->id = *id;
		if (!node_id_valid(id))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Invalid node id %s",
				      type_to_string(tmpctx, struct node_id,
						     id));
	} else {
		memset(&c->id, 0, sizeof(c->id));
	}
	c->dbid = dbid;

	c->capabilities = capabilities;
	c->chainparams = chainparams;

	/*~ This is the core of ccan/io: the connection creation calls a
	 * callback which returns the initial plan to execute: in our case,
	 * read a message.*/
	c->conn = io_new_conn(ctx, fd, client_read_next, c);

	/*~ tal_steal() moves a pointer to a new parent.  At this point, the
	 * hierarchy is:
	 *
	 *   ctx -> c
	 *   ctx -> c->conn
	 *
	 * We want to the c->conn to own 'c', so that if the io_conn closes,
	 * the client is freed:
	 *
	 *   ctx -> c->conn -> c.
	 */
	tal_steal(c->conn, c);

	/* We put the special zero-db HSM connections into an array, the rest
	 * go into the map. */
	if (dbid == 0) {
		assert(num_dbid_zero_clients < ARRAY_SIZE(dbid_zero_clients));
		dbid_zero_clients[num_dbid_zero_clients++] = c;
		c->hsmd_client = hsmd_client_new_main(c, c->capabilities, c);
	} else {
		struct client *old_client = uintmap_get(&clients, dbid);

		/* Close conn and free any old client of this dbid. */
		if (old_client)
			io_close(old_client->conn);

		if (!uintmap_add(&clients, dbid, c))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Failed inserting dbid %"PRIu64, dbid);
		tal_add_destructor(c, destroy_client);
		c->hsmd_client =
		    hsmd_client_new_peer(c, c->capabilities, dbid, id, c);
	}

	return c;
}

/* This is the common pattern for the tail of each handler in this file. */
static struct io_plan *req_reply(struct io_conn *conn,
				 struct client *c,
				 const u8 *msg_out TAKES)
{
	/*~ Write this out, then read the next one.  This works perfectly for
	 * a simple request/response system like this.
	 *
	 * Internally, the ccan/io subsystem gathers all the file descriptors,
	 * figures out which want to write and read, asks the OS which ones
	 * are available, and for those file descriptors, tries to do the
	 * reads/writes we've asked it.  It handles retry in the case where a
	 * read or write is done partially.
	 *
	 * Since the OS does buffering internally (on my system, over 100k
	 * worth) writes will normally succeed immediately.  However, if the
	 * client is slow or malicious, and doesn't read from the socket as
	 * fast as we're writing, eventually the socket buffer will fill up;
	 * we don't care, because ccan/io will wait until there's room to
	 * write this reply before it will read again.  The client just hurts
	 * themselves, and there's no Denial of Service on us.
	 *
	 * If we were to queue outgoing messages ourselves, we *would* have to
	 * consider such scenarios; this is why our daemons generally avoid
	 * buffering from untrusted parties. */
	return io_write_wire(conn, msg_out, client_read_next, c);
}

/*~ This encrypts the content of the `struct secret hsm_secret` and
 * stores it in hsm_secret, this is called instead of create_hsm() if
 * `lightningd` is started with --encrypted-hsm.
 */
static void create_encrypted_hsm(int fd, const struct secret *encryption_key)
{
	struct encrypted_hsm_secret cipher;

	if (!encrypt_hsm_secret(encryption_key, &hsm_secret,
				&cipher))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Encrypting hsm_secret");
	if (!write_all(fd, cipher.data, ENCRYPTED_HSM_SECRET_LEN)) {
		unlink_noerr("hsm_secret");
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
		              "Writing encrypted hsm_secret: %s", strerror(errno));
	}
}

static void create_hsm(int fd)
{
	/*~ ccan/read_write_all has a more convenient return than write() where
	 * we'd have to check the return value == the length we gave: write()
	 * can return short on normal files if we run out of disk space. */
	if (!write_all(fd, &hsm_secret, sizeof(hsm_secret))) {
		/* ccan/noerr contains useful routines like this, which don't
		 * clobber errno, so we can use it in our error report. */
		unlink_noerr("hsm_secret");
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
		              "writing: %s", strerror(errno));
	}
}

/*~ We store our root secret in a "hsm_secret" file (like all of Core Lightning,
 * we run in the user's .lightning directory). */
static void maybe_create_new_hsm(const struct secret *encryption_key,
                                 bool random_hsm)
{
	/*~ Note that this is opened for write-only, even though the permissions
	 * are set to read-only.  That's perfectly valid! */
	int fd = open("hsm_secret", O_CREAT|O_EXCL|O_WRONLY, 0400);
	if (fd < 0) {
		/* If this is not the first time we've run, it will exist. */
		if (errno == EEXIST)
			return;
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
		              "creating: %s", strerror(errno));
	}

	/*~ This is libsodium's cryptographic randomness routine: we assume
	 * it's doing a good job. */
	if (random_hsm)
		randombytes_buf(&hsm_secret, sizeof(hsm_secret));

	/*~ If an encryption_key was provided, store an encrypted seed. */
	if (encryption_key)
		create_encrypted_hsm(fd, encryption_key);
	/*~ Otherwise store the seed in clear.. */
	else
		create_hsm(fd);
	/*~ fsync (mostly!) ensures that the file has reached the disk. */
	if (fsync(fd) != 0) {
		unlink_noerr("hsm_secret");
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "fsync: %s", strerror(errno));
	}
	/*~ This should never fail if fsync succeeded.  But paranoia good, and
	 * bugs exist. */
	if (close(fd) != 0) {
		unlink_noerr("hsm_secret");
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "closing: %s", strerror(errno));
	}
	/*~ We actually need to sync the *directory itself* to make sure the
	 * file exists!  You're only allowed to open directories read-only in
	 * modern Unix though. */
	fd = open(".", O_RDONLY);
	if (fd < 0) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "opening: %s", strerror(errno));
	}
	if (fsync(fd) != 0) {
		unlink_noerr("hsm_secret");
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "fsyncdir: %s", strerror(errno));
	}
	close(fd);
	/*~ status_unusual() is good for things which are interesting and
	 * definitely won't spam the logs.  Only status_broken() is higher;
	 * status_info() is lower, then status_debug() and finally
	 * status_io(). */
	status_unusual("HSM: created new hsm_secret file");
}

/*~ We always load the HSM file, even if we just created it above.  This
 * both unifies the code paths, and provides a nice sanity check that the
 * file contents are as they will be for future invocations. */
static void load_hsm(const struct secret *encryption_key)
{
	struct stat st;
	int fd = open("hsm_secret", O_RDONLY);
	if (fd < 0)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "opening: %s", strerror(errno));
	if (stat("hsm_secret", &st) != 0)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
		              "stating: %s", strerror(errno));

	/* If the seed is stored in clear. */
	if (st.st_size == 32) {
		if (!read_all(fd, &hsm_secret, sizeof(hsm_secret)))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
			              "reading: %s", strerror(errno));
		/* If an encryption key was passed with a not yet encrypted hsm_secret,
		 * remove the old one and create an encrypted one. */
		if (encryption_key) {
			if (close(fd) != 0)
				status_failed(STATUS_FAIL_INTERNAL_ERROR,
				              "closing: %s", strerror(errno));
			if (remove("hsm_secret") != 0)
				status_failed(STATUS_FAIL_INTERNAL_ERROR,
				              "removing clear hsm_secret: %s", strerror(errno));
			maybe_create_new_hsm(encryption_key, false);
			fd = open("hsm_secret", O_RDONLY);
			if (fd < 0)
				status_failed(STATUS_FAIL_INTERNAL_ERROR,
				              "opening: %s", strerror(errno));
		}
	}
	/* If an encryption key was passed and the `hsm_secret` is stored
	 * encrypted, recover the seed from the cipher. */
	else if (st.st_size == ENCRYPTED_HSM_SECRET_LEN) {
		struct encrypted_hsm_secret encrypted_secret;

		/* hsm_control must have checked it! */
		assert(encryption_key);

		if (!read_all(fd, encrypted_secret.data, ENCRYPTED_HSM_SECRET_LEN))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
			              "Reading encrypted hsm_secret: %s", strerror(errno));
		if (!decrypt_hsm_secret(encryption_key, &encrypted_secret,
					&hsm_secret)) {
			/* Exit but don't throw a backtrace when the user made a mistake in typing
			 * its password. Instead exit and `lightningd` will be able to give
			 * an error message. */
			exit(1);
		}
	}
	else
		status_failed(STATUS_FAIL_INTERNAL_ERROR, "Invalid hsm_secret, "
							  "no plaintext nor encrypted"
							  " seed.");
	close(fd);
}

/*~ This is the response to lightningd's HSM_INIT request, which is the first
 * thing it sends. */
static struct io_plan *init_hsm(struct io_conn *conn,
				struct client *c,
				const u8 *msg_in)
{
	struct privkey *privkey;
	struct secret *seed;
	struct secrets *secrets;
	struct sha256 *shaseed;
	struct secret *hsm_encryption_key;
	struct bip32_key_version bip32_key_version;

	/* This must be lightningd. */
	assert(is_lightningd(c));

	/*~ The fromwire_* routines are autogenerated, based on the message
	 * definitions in hsm_client_wire.csv.  The format of those files is
	 * an extension of the simple comma-separated format output by the
	 * BOLT tools/extract-formats.py tool. */
	if (!fromwire_hsmd_init(NULL, msg_in, &bip32_key_version, &chainparams,
	                       &hsm_encryption_key, &privkey, &seed, &secrets, &shaseed))
		return bad_req(conn, c, msg_in);

	/*~ The memory is actually copied in towire(), so lock the `hsm_secret`
	 * encryption key (new) memory again here. */
	if (hsm_encryption_key && sodium_mlock(hsm_encryption_key,
	                                       sizeof(hsm_encryption_key)) != 0)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
		              "Could not lock memory for hsm_secret encryption key.");
	/*~ Don't swap this. */
	sodium_mlock(hsm_secret.data, sizeof(hsm_secret.data));

#if DEVELOPER
	dev_force_privkey = privkey;
	dev_force_bip32_seed = seed;
	dev_force_channel_secrets = secrets;
	dev_force_channel_secrets_shaseed = shaseed;
#endif

	/* Once we have read the init message we know which params the master
	 * will use */
	c->chainparams = chainparams;
	maybe_create_new_hsm(hsm_encryption_key, true);
	load_hsm(hsm_encryption_key);

	/*~ We don't need the hsm_secret encryption key anymore. */
	if (hsm_encryption_key)
		discard_key(take(hsm_encryption_key));

	return req_reply(conn, c, hsmd_init(hsm_secret, bip32_key_version));
}

/*~ Since we process requests then service them in strict order, and because
 * only lightningd can request a new client fd, we can get away with a global
 * here!  But because we are being tricky, I set it to an invalid value when
 * not in use, and sprinkle assertions around. */
static int pending_client_fd = -1;

/*~ This is the callback from below: having sent the reply, we now send the
 * fd for the client end of the new socketpair. */
static struct io_plan *send_pending_client_fd(struct io_conn *conn,
					      struct client *master)
{
	int fd = pending_client_fd;
	/* This must be the master. */
	assert(is_lightningd(master));
	assert(fd != -1);

	/* This sanity check shouldn't be necessary, but it's cheap. */
	pending_client_fd = -1;

	/*~There's arcane UNIX magic to send an open file descriptor over a
	 * UNIX domain socket.  There's no great way to autogenerate this
	 * though; especially for the receive side, so we always pass these
	 * manually immediately following the message.
	 *
	 * io_send_fd()'s third parameter is whether to close the local one
	 * after sending; that saves us YA callback.
	 */
	return io_send_fd(conn, fd, true, client_read_next, master);
}

/*~ This is used by the master to create a new client connection (which
 * becomes the HSM_FD for the subdaemon after forking). */
static struct io_plan *pass_client_hsmfd(struct io_conn *conn,
					 struct client *c,
					 const u8 *msg_in)
{
	int fds[2];
	u64 dbid, capabilities;
	struct node_id id;

	/* This must be lightningd itself. */
	assert(is_lightningd(c));

	if (!fromwire_hsmd_client_hsmfd(msg_in, &id, &dbid, &capabilities))
		return bad_req(conn, c, msg_in);

	/* socketpair is a bi-directional pipe, which is what we want. */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		status_failed(STATUS_FAIL_INTERNAL_ERROR, "creating fds: %s",
			      strerror(errno));

	status_debug("new_client: %"PRIu64, dbid);
	new_client(c, c->chainparams, &id, dbid, capabilities, fds[0]);

	/*~ We stash this in a global, because we need to get both the fd and
	 * the client pointer to the callback.  The other way would be to
	 * create a boutique structure and hand that, but we don't need to. */
	pending_client_fd = fds[1];
	return io_write_wire(conn, take(towire_hsmd_client_hsmfd_reply(NULL)),
			     send_pending_client_fd, c);
}

#if DEVELOPER
static struct io_plan *handle_memleak(struct io_conn *conn,
				      struct client *c,
				      const u8 *msg_in)
{
	struct htable *memtable;
	bool found_leak;
	u8 *reply;

	memtable = memleak_find_allocations(tmpctx, msg_in, msg_in);

	/* Now delete clients and anything they point to. */
	memleak_remove_region(memtable,
			      dbid_zero_clients, sizeof(dbid_zero_clients));
	memleak_remove_uintmap(memtable, &clients);
	memleak_remove_region(memtable,
			      status_conn, tal_bytelen(status_conn));

	memleak_remove_pointer(memtable, dev_force_privkey);
	memleak_remove_pointer(memtable, dev_force_bip32_seed);

	found_leak = dump_memleak(memtable, memleak_status_broken);
	reply = towire_hsmd_dev_memleak_reply(NULL, found_leak);
	return req_reply(conn, c, take(reply));
}
#endif /* DEVELOPER */

u8 *hsmd_status_bad_request(struct hsmd_client *client, const u8 *msg, const char *error)
{
	/* Extract the pointer to the hsmd representation of the
	 * client which has access to the underlying connection. */
	struct client *c = (struct client*)client->extra;
	bad_req_fmt(c->conn, c, msg, "%s", error);

	/* We often use `return hsmd_status_bad_request` to drop out, and NULL
	 * means we encountered an error. */
	return NULL;
}

void hsmd_status_fmt(enum log_level level, const struct node_id *peer,
		     const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	status_vfmt(level, peer, fmt, ap);
	va_end(ap);
}

void hsmd_status_failed(enum status_failreason reason, const char *fmt, ...)
{
	va_list ap;
	char *str;

	va_start(ap, fmt);
	str = tal_vfmt(NULL, fmt, ap);
	va_end(ap);

	/* Give a nice backtrace when this happens! */
	if (reason == STATUS_FAIL_INTERNAL_ERROR)
		send_backtrace(str);

	status_send_fatal(take(towire_status_fail(NULL, reason, str)));
}

/*~ This is the core of the HSM daemon: handling requests. */
static struct io_plan *handle_client(struct io_conn *conn, struct client *c)
{
	enum hsmd_wire t = fromwire_peektype(c->msg_in);

	if (!is_lightningd(c))
		status_peer_debug(&c->id, "Got %s", hsmd_wire_name(t));

	/* Before we do anything else, is this client allowed to do
	 * what he asks for? */
	if (!hsmd_check_client_capabilities(c->hsmd_client, t))
		return bad_req_fmt(conn, c, c->msg_in,
				   "client does not have capability to run %d",
				   t);

	/* Now actually go and do what the client asked for */
	switch (t) {
	case WIRE_HSMD_INIT:
		return init_hsm(conn, c, c->msg_in);

	case WIRE_HSMD_CLIENT_HSMFD:
		return pass_client_hsmfd(conn, c, c->msg_in);

#if DEVELOPER
	case WIRE_HSMD_DEV_MEMLEAK:
		return handle_memleak(conn, c, c->msg_in);
#else
	case WIRE_HSMD_DEV_MEMLEAK:
#endif /* DEVELOPER */

	case WIRE_HSMD_NEW_CHANNEL:
	case WIRE_HSMD_READY_CHANNEL:
	case WIRE_HSMD_SIGN_COMMITMENT_TX:
	case WIRE_HSMD_VALIDATE_COMMITMENT_TX:
	case WIRE_HSMD_VALIDATE_REVOCATION:
	case WIRE_HSMD_SIGN_PENALTY_TO_US:
	case WIRE_HSMD_SIGN_REMOTE_COMMITMENT_TX:
	case WIRE_HSMD_SIGN_REMOTE_HTLC_TX:
	case WIRE_HSMD_SIGN_MUTUAL_CLOSE_TX:
	case WIRE_HSMD_GET_PER_COMMITMENT_POINT:
	case WIRE_HSMD_SIGN_WITHDRAWAL:
	case WIRE_HSMD_GET_CHANNEL_BASEPOINTS:
	case WIRE_HSMD_SIGN_INVOICE:
	case WIRE_HSMD_SIGN_MESSAGE:
	case WIRE_HSMD_SIGN_OPTION_WILL_FUND_OFFER:
	case WIRE_HSMD_SIGN_BOLT12:
	case WIRE_HSMD_ECDH_REQ:
	case WIRE_HSMD_CHECK_FUTURE_SECRET:
	case WIRE_HSMD_GET_OUTPUT_SCRIPTPUBKEY:
	case WIRE_HSMD_DERIVE_SECRET:
	case WIRE_HSMD_CANNOUNCEMENT_SIG_REQ:
	case WIRE_HSMD_NODE_ANNOUNCEMENT_SIG_REQ:
	case WIRE_HSMD_CUPDATE_SIG_REQ:
	case WIRE_HSMD_SIGN_LOCAL_HTLC_TX:
	case WIRE_HSMD_SIGN_REMOTE_HTLC_TO_US:
	case WIRE_HSMD_SIGN_DELAYED_PAYMENT_TO_US:
		/* Hand off to libhsmd for processing */
		return req_reply(conn, c,
				 take(hsmd_handle_client_message(
				     tmpctx, c->hsmd_client, c->msg_in)));

	case WIRE_HSMD_ECDH_RESP:
	case WIRE_HSMD_CANNOUNCEMENT_SIG_REPLY:
	case WIRE_HSMD_CUPDATE_SIG_REPLY:
	case WIRE_HSMD_CLIENT_HSMFD_REPLY:
	case WIRE_HSMD_NEW_CHANNEL_REPLY:
	case WIRE_HSMD_READY_CHANNEL_REPLY:
	case WIRE_HSMD_NODE_ANNOUNCEMENT_SIG_REPLY:
	case WIRE_HSMD_SIGN_WITHDRAWAL_REPLY:
	case WIRE_HSMD_SIGN_INVOICE_REPLY:
	case WIRE_HSMD_INIT_REPLY:
	case WIRE_HSMD_DERIVE_SECRET_REPLY:
	case WIRE_HSMSTATUS_CLIENT_BAD_REQUEST:
	case WIRE_HSMD_SIGN_COMMITMENT_TX_REPLY:
	case WIRE_HSMD_VALIDATE_COMMITMENT_TX_REPLY:
	case WIRE_HSMD_VALIDATE_REVOCATION_REPLY:
	case WIRE_HSMD_SIGN_TX_REPLY:
	case WIRE_HSMD_SIGN_OPTION_WILL_FUND_OFFER_REPLY:
	case WIRE_HSMD_GET_PER_COMMITMENT_POINT_REPLY:
	case WIRE_HSMD_CHECK_FUTURE_SECRET_REPLY:
	case WIRE_HSMD_GET_CHANNEL_BASEPOINTS_REPLY:
	case WIRE_HSMD_DEV_MEMLEAK_REPLY:
	case WIRE_HSMD_SIGN_MESSAGE_REPLY:
	case WIRE_HSMD_GET_OUTPUT_SCRIPTPUBKEY_REPLY:
	case WIRE_HSMD_SIGN_BOLT12_REPLY:
		return bad_req_fmt(conn, c, c->msg_in,
				   "Received an incoming message of type %s, "
				   "which is not a request",
				   hsmd_wire_name(t));
	}

	return bad_req_fmt(conn, c, c->msg_in, "Unknown request");
}

static void master_gone(struct io_conn *unused UNUSED, struct client *c UNUSED)
{
	daemon_shutdown();
	/* Can't tell master, it's gone. */
	exit(2);
}

int main(int argc, char *argv[])
{
	struct client *master;

	setup_locale();

	/* This sets up tmpctx, various DEVELOPER options, backtraces, etc. */
	subdaemon_setup(argc, argv);

	/* A trivial daemon_conn just for writing. */
	status_conn = daemon_conn_new(NULL, STDIN_FILENO, NULL, NULL, NULL);
	status_setup_async(status_conn);
	uintmap_init(&clients);

	master = new_client(NULL, NULL, NULL, 0,
			    HSM_CAP_MASTER | HSM_CAP_SIGN_GOSSIP | HSM_CAP_ECDH,
			    REQ_FD);

	/* First client == lightningd. */
	assert(is_lightningd(master));

	/* When conn closes, everything is freed. */
	io_set_finish(master->conn, master_gone, master);

	/*~ The two NULL args are a list of timers, and the timer which expired:
	 * we don't have any timers. */
	io_loop(NULL, NULL);

	/*~ This should never be reached: io_loop only exits on io_break which
	 * we don't call, a timer expiry which we don't have, or all connections
	 * being closed, and closing the master calls master_gone. */
	abort();
}

/*~ Congratulations on making it through the first of the seven dwarves!
 * (And Christian wondered why I'm so fond of having separate daemons!).
 *
 * We continue our story in the next-more-complex daemon: connectd/connectd.c
 */
