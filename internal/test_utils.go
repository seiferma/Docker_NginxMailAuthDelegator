package internal

import (
	"strings"
	"testing"
)

func assertNonNil(t *testing.T, actual interface{}) {
	if actual == nil {
		t.Fatal("Expected non-nil but got nil.")
	}
}

func assertNil(t *testing.T, actual interface{}) {
	if actual != nil {
		t.Fatalf("Expected nil but got %v.", actual)
	}
}

func assertStringEquals(t *testing.T, expected, actual string) {
	if strings.Compare(actual, expected) != 0 {
		t.Fatalf("Expected %v but got %v.", expected, actual)
	}
}

func assertEquals(t *testing.T, expected, actual interface{}) {
	if expected != actual {
		t.Fatalf("Expected %v but got %v.", expected, actual)
	}
}

func assertStringNotEquals(t *testing.T, expected, actual string) {
	if strings.Compare(actual, expected) == 0 {
		t.Fatalf("Expected not %v but got %v.", expected, actual)
	}
}

func assertStringArraysEquals(t *testing.T, expected, actual []string) {
	if len(expected) != len(actual) {
		t.Fatalf("Expected %v elements but got %v elements.", len(expected), len(actual))
	}
	for i := 0; i < len(expected); i++ {
		if expected[i] != actual[i] {
			t.Fatalf("Expected %v at position %v, but got %v.", expected[i], i, actual[i])
		}
	}
}
