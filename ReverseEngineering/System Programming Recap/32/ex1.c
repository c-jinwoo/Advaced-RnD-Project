#include <stdio.h>
#include <stdlib.h>

struct Point {
	double x;
	double y;
};

void Point_print(const struct Point *self);

int main(){
	struct Point aPoint;
	aPoint.x = 1.0;
	aPoint.y = 2.0;

	struct Point bPoint = { 0 };
	
	struct Point cPoint = { 1.0, 2.0 };

	Point_print(&aPoint);	
	Point_print(&bPoint);
	Point_print(&cPoint);

	return 0;
}

void Point_print(const struct Point *self){
	printf("(%f, %f)\n", (*self).x, (*self).y);
}
