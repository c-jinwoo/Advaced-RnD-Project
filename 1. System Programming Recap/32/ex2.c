#include <stdio.h>
#include <stdlib.h>

typedef struct Point {
	double x;
	double y;
} Point;

void Point_print(const Point *self);

int main(){
	Point point = { 4.0, 8.0 };
	Point_print(&point);
}

void Point_print(const Point *self){
	printf("(%f, %f)\n", (*self).x, (*self).y);
}
