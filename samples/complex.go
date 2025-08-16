package main

import (
	"fmt"
	"strconv"
)

func fibonacci(n int) int {
	if n <= 1 {
		return n
	}
	return fibonacci(n-1) + fibonacci(n-2)
}

func main() {
	for i := 0; i < 10; i++ {
		fib := fibonacci(i)
		fmt.Printf("fibonacci(%d) = %d\n", i, fib)
	}
	
	// Some string operations
	numbers := []string{"1", "2", "3", "4", "5"}
	for _, numStr := range numbers {
		num, err := strconv.Atoi(numStr)
		if err == nil {
			fmt.Printf("Number: %d, Square: %d\n", num, num*num)
		}
	}
}