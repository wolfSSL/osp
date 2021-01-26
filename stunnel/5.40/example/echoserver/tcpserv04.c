#include	"unp.h"

void
str_echo(int sockfd)
{
	ssize_t		n;
	char		buf[MAXLINE];


again:
	while ( (n = Read(sockfd, buf, MAXLINE)) > 0) {
		Writen(sockfd, __FILE__, sizeof __FILE__);
		Writen(sockfd, "\n", 1);
    }

	if (n < 0 && errno == EINTR)
		goto again;
	else if (n < 0)
		err_sys("str_echo: read error");
}

int
main(int argc, char **argv)
{
	int					listenfd, connfd;
	pid_t				childpid;
	socklen_t			clilen;
	struct sockaddr_in	cliaddr, servaddr;
	char				buff[MAXLINE];
	int					optval;				/* flag value for setsockopt */

	listenfd = Socket(AF_INET, SOCK_STREAM, 0);
	
	/* setsockopt: Eliminates "ERROR on binding: Address already in use"
     * error. */
	optval = 1;
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
               sizeof(int));

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family      = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	servaddr.sin_port        = htons(11112);

	Bind(listenfd, (SA *) &servaddr, sizeof(servaddr));

	Listen(listenfd, LISTENQ);

	for ( ; ; ) {
		clilen = sizeof(cliaddr);
		if ( (connfd = accept(listenfd, (SA *) &cliaddr, &clilen)) < 0) 
		{
			if (errno == EINTR)
				continue;		/* back to for() */
			else
				err_sys("accept error");
		}
		
		printf("Connection from %s, port %d\n", 
				inet_ntop(AF_INET, &cliaddr.sin_addr, buff, sizeof(buff)),
				ntohs(cliaddr.sin_port));

		str_echo(connfd);		/* process the request */
		Close(connfd);			/* close connected socket */
	}
}
