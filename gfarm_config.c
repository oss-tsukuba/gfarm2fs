#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <ctype.h>
#include <gfarm/gfarm.h>
#include "gfarm_config.h"

/* *userp should *not* be free'ed */
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

/* *metadbp should *not* be free'ed */
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

/* GSI */

#define XATTR_MAX	4096

/* *value should be free'ed */
static gfarm_error_t
gfarm_config_gsi_common(char *cmd, int offset_to_filename, int one_line,
	char **valuep)
{
	char line[XATTR_MAX];
	char *filename = cmd + offset_to_filename;
	int fd = mkstemp(filename), status, i, err = 0;
	ssize_t size;
	gfarm_error_t e = GFARM_ERR_NO_ERROR;

	if (fd == -1)
		return (gfarm_errno_to_error(errno));
	close(fd);
	status = system(cmd);
	if (status == -1) {
		e = gfarm_errno_to_error(errno);
		goto unlink;
	}
	if (WEXITSTATUS(status) != 0)
		err = 1;
	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		e = gfarm_errno_to_error(errno);
		goto unlink;
	}
	size = read(fd, line, sizeof line);
	if (size > 0) {
		if (size == sizeof line)
			--size;
		line[size] = '\0';
		if (one_line && !err) {
			for (i = 0; i < size && line[i] != '\n'; ++i)
				;
			line[i] = '\0';
		}
		if (valuep != NULL) {
			*valuep = strdup(line);
			if (*valuep == NULL)
				e = GFARM_ERR_NO_MEMORY;
		}
	} else if (size == 0)
		e = GFARM_ERR_NO_SUCH_OBJECT;
	else
		e = gfarm_errno_to_error(errno);
	close(fd);
unlink:
	unlink(filename);
	return (e);
}

/* *infop should be free'ed */
gfarm_error_t
gfarm_config_gsi_proxy_info(char **infop)
{
	char cmd[] = "(grid-proxy-info 2>&1) > /tmp/gfarm2fs-XXXXXX";
	/* offset to            1111111111222222 */
	/* filename   01234567890123456789012345 */
	int offset_to_filename = 25;

	return (gfarm_config_gsi_common(cmd, offset_to_filename, 0, infop));
}

/* *pathp should be free'ed */
gfarm_error_t
gfarm_config_gsi_path(char **pathp)
{
	char cmd[] = "grid-proxy-info | awk '/path/{print $3}' > "
		"/tmp/gfarm2fs-XXXXXX";
	/* offset to            1111111111222222222233333333334444 */
	/* filename   01234567890123456789012345678901234567890123 */
	int offset_to_filename = 43;

	return (gfarm_config_gsi_common(cmd, offset_to_filename, 1, pathp));
}

/* *timeleftp should be free'ed */
gfarm_error_t
gfarm_config_gsi_timeleft(char **leftp)
{
	char cmd[] = "grid-proxy-info | awk '/timeleft/{print $3}' > "
		"/tmp/gfarm2fs-XXXXXX";
	/* offset to            11111111112222222222333333333344444444 */
	/* filename   012345678901234567890123456789012345678901234567 */
	int offset_to_filename = 47;

	return (gfarm_config_gsi_common(cmd, offset_to_filename, 1, leftp));
}
