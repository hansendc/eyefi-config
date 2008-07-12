
int fd_set_no_cache(int fd)
{
	//fcntl(fd, F_SETFL, O_DIRECT);
	return fcntl(fd, F_NOCACHE, 1);
}


