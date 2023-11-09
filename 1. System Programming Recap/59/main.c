#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#define BUFFER_SIZE 80

char buffer[BUFFER_SIZE];

int main(int argc, char* argv[]){
	ssize_t bytes_read;
	int fd = STDIN_FILENO;
	
	if(argc > 1){
		if((fd = open(argv[1], O_RDONLY)) < 0){
			write(STDERR_FILENO, "NO FILE\n", strlen("NO FILE\n"));
			exit(EXIT_FAILURE);
		}				
	}

	while(bytes_read = read(fd, buffer, BUFFER_SIZE)){
		write(STDOUT_FILENO, buffer, bytes_read);
	}

	close(fd);

	return 0;
}
