package main

import "fmt"

// A more complex example to test decompiler accuracy
func calculator(operation string, a, b float64) float64 {
	switch operation {
	case "add":
		return a + b
	case "subtract":
		return a - b
	case "multiply":
		return a * b
	case "divide":
		if b != 0 {
			return a / b
		}
		return 0
	default:
		return 0
	}
}

func fibonacci(n int) int {
	if n <= 1 {
		return n
	}
	return fibonacci(n-1) + fibonacci(n-2)
}

func processNumbers() {
	numbers := []int{1, 2, 3, 4, 5}
	fmt.Println("Processing numbers:")
	
	for i, num := range numbers {
		square := num * num
		fmt.Printf("Index %d: %d squared = %d\n", i, num, square)
	}
}

func main() {
	fmt.Println("=== Go Decompiler Accuracy Test ===")
	
	// Test calculator function
	result := calculator("add", 10.5, 5.2)
	fmt.Printf("Calculator result: %.2f\n", result)
	
	// Test fibonacci function
	fmt.Println("Fibonacci sequence:")
	for i := 0; i < 8; i++ {
		fib := fibonacci(i)
		fmt.Printf("F(%d) = %d\n", i, fib)
	}
	
	// Test array processing
	processNumbers()
	
	fmt.Println("Test completed successfully!")
}