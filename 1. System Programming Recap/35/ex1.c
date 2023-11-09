#include <stdio.h>
#include <stdlib.h>
#include "Point.h"

int main(){
	Point a = Point_value(1.0, 2.0);
	Point_print(&a);

	Point b = Point_value(10.0, 10.0);
	Point_print(&b);

	return 0;
}
