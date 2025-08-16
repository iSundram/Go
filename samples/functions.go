package main

import "fmt"

func add(a, b int) int {
	return a + b
}

func greet(name string) string {
	return "Hello, " + name
}

func main() {
	result := add(5, 3)
	fmt.Printf("5 + 3 = %d\n", result)
	
	greeting := greet("Go Decompiler")
	fmt.Println(greeting)
}