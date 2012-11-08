#include <stdlib.h>
#include <gfarm/gfarm.h>
#include "gfarm_config.h"

/* *userp should not be free'ed */
gfarm_error_t
gfarm_config_user(const char *path, const char **userp)
{
	struct gfm_connection *gfm_server;
	gfarm_error_t e;

	if (path == NULL)
		path = GFARM_PATH_ROOT;
	if ((e = gfm_client_connection_and_process_acquire_by_path(
	    path, &gfm_server)) != GFARM_ERR_NO_ERROR)
		return (e);
	if (userp != NULL)
		*userp = gfm_client_username(gfm_server);
	gfm_client_connection_free(gfm_server);

	return (GFARM_ERR_NO_ERROR);
}

/* *metadbp should not be free'ed */
gfarm_error_t
gfarm_config_metadb_server(const char *path, const char **metadbp, int *portp)
{
	struct gfm_connection *gfm_server;
	struct gfarm_metadb_server *ms;
	gfarm_error_t e;

	if (path == NULL)
		path = GFARM_PATH_ROOT;
	if ((e = gfm_client_connection_and_process_acquire_by_path(
	    path, &gfm_server)) != GFARM_ERR_NO_ERROR)
		return (e);
	ms = gfm_client_connection_get_real_server(gfm_server);
	if (metadbp != NULL)
		*metadbp = gfarm_metadb_server_get_name(ms);
	if (portp != NULL)
		*portp = gfarm_metadb_server_get_port(ms);
	gfm_client_connection_free(gfm_server);

	return (GFARM_ERR_NO_ERROR);
}
