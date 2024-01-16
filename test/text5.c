#include <stdio.h>

int add(int a, int b){
    return a+b;
}

int main(){
    int a = 3;
    int b = 5;
    printf("%d",add(a,b));
}