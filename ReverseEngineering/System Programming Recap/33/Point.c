#include <stdio.h>
#include "Point.h"

Point Point_value(double x, double y){
	Point initialized = { x, y };
	return initialized;
}

void Point_offset(Point *self, const Point *offset_by){
	self->x += offset_by->x;
	self->y += offset_by->y;
}

void Point_print(Point *self){
	printf("Point: (%f, %f)\n", self->x, self->y);
}
