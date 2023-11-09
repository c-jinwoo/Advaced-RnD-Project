#include <stdio.h>
#include <stdlib.h>
#include "Point.h"

void *OOM_GUARD(void *p);

int main(){
	Point a = Point_value(1.0, 2.0);
	Point_print(&a);

	Point b = Point_value(10.0, 10.0);
	Point_offset(&a, &b);
	Point_print(&a);

	// define c as a pointer
	Point *c = OOM_GUARD(malloc(sizeof(Point)));
	*c = Point_value(1.0, 2.0);
	Point_print(c);
	free(c);
	
	return 0;
}

void *OOM_GUARD(void *p){
	if(p == NULL){
		fprintf(stderr, "out of memory\n");
		exit(EXIT_FAILURE);
	}
	return p;
}
