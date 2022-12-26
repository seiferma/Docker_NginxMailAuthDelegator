package asserts

import (
	"testing"
)

func AssertNonNil(t *testing.T, actual interface{}) {
	if actual == nil {
		t.Fatal("Expected non-nil but got nil.")
	}
}

func AssertNil(t *testing.T, actual interface{}) {
	if actual != nil {
		t.Fatalf("Expected nil but got %v.", actual)
	}
}

func AssertEquals(t *testing.T, expected, actual interface{}) {
	if expected != actual {
		t.Fatalf("Expected %v but got %v.", expected, actual)
	}
}

func AssertNotEquals(t *testing.T, expected, actual interface{}) {
	if expected == actual {
		t.Fatalf("Did not expect %v but got %v.", expected, actual)
	}
}

func AssertStringArraysEquals(t *testing.T, expected, actual []string) {
	if len(expected) != len(actual) {
		t.Fatalf("Expected %v elements but got %v elements.", len(expected), len(actual))
	}
	for i := 0; i < len(expected); i++ {
		if expected[i] != actual[i] {
			t.Fatalf("Expected %v at position %v, but got %v.", expected[i], i, actual[i])
		}
	}
}
