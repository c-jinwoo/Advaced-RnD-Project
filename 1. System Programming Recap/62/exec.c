#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/wait.h>

int main(){
	char *command[] = {"grep", "-E", "c$", "-", 0};
	char *bin_file = command[0];
	
	if(fork() == 0){
		// Child process
		int redirect_fd = open("./redirect_fd.txt", O_CREAT | O_TRUNC | O_WRONLY, 0644);
		dup2(redirect_fd, STDOUT_FILENO);
		close(redirect_fd);
	
		if(execvp(bin_file, command) == -1){
			fprintf(stderr, "Error executing %s\n", bin_file);			
		}
	}
	else{
		// Parent Process
		wait(NULL);
		printf("done!\n");
	}

	return 0;
}
