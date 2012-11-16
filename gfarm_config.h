/* lookup.h */
struct gfm_connection;
gfarm_error_t gfm_client_connection_and_process_acquire_by_path(const char *,
	struct gfm_connection **);

/* gfm_client.h */
const char *gfm_client_username(struct gfm_connection *);
void gfm_client_connection_free(struct gfm_connection *);
struct gfarm_metadb_server *gfm_client_connection_get_real_server(
	struct gfm_connection *);

/* metadb_server.h */
const char * gfarm_metadb_server_get_name(struct gfarm_metadb_server *);
int gfarm_metadb_server_get_port(struct gfarm_metadb_server *);

gfarm_error_t gfarm_config_user(const char *, const char **);
gfarm_error_t gfarm_config_metadb_server(const char *, const char **, int *);
gfarm_error_t gfarm_config_gsi_proxy_info(char **);
gfarm_error_t gfarm_config_gsi_path(char **);
gfarm_error_t gfarm_config_gsi_timeleft(char **);
