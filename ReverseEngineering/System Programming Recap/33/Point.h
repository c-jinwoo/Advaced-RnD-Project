#ifndef POINT_H
#define POINT_H

typedef struct Point {
	double x;
	double y;
} Point;

/*
 * Initialize and return a point struct value
 */
Point Point_value(double x, double y);

/**
 * Offset a Point by another point
 */
void Point_offset(Point *self, const Point *offset_by);

void Point_print(Point *self);

#endif
