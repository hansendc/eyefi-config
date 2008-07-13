
int fd_set_no_cache(int fd)
{
	return fcntl(fd, F_NOCACHE, 1);
}


