package main

import (
	"reflect"
	"testing"
)

// decodeStringList reads the module selection the dashboard sends with
// start_assessment. This is the wire that did not exist before: the operator's
// selection was persisted to the assessments row but never transmitted, so the
// agent ran "all" while the report claimed otherwise.

func TestDecodeStringListArray(t *testing.T) {
	got := decodeStringList([]interface{}{"malware", "identity"})
	want := []string{"malware", "identity"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("array: got %v, want %v", got, want)
	}
}

func TestDecodeStringListGoSlice(t *testing.T) {
	got := decodeStringList([]string{"malware", "network"})
	want := []string{"malware", "network"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("[]string: got %v, want %v", got, want)
	}
}

func TestDecodeStringListCSV(t *testing.T) {
	got := decodeStringList("malware, identity ,network")
	want := []string{"malware", "identity", "network"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("csv: got %v, want %v", got, want)
	}
}

func TestDecodeStringListTrimsAndDropsBlanks(t *testing.T) {
	got := decodeStringList([]interface{}{" malware ", "", "   ", "identity"})
	want := []string{"malware", "identity"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("blanks: got %v, want %v", got, want)
	}
}

// An absent key must mean "run everything" (nil), not an empty non-nil slice,
// because the caller treats len==0 as the "all" sentinel.
func TestDecodeStringListAbsentIsNil(t *testing.T) {
	for name, in := range map[string]interface{}{
		"nil":       nil,
		"number":    42,
		"bool":      true,
		"emptyArr":  []interface{}{},
		"emptyStr":  "",
		"onlyComma": ",,,",
	} {
		got := decodeStringList(in)
		if len(got) != 0 {
			t.Errorf("%s: got %v, want empty", name, got)
		}
	}
}

// Non-string entries in the array must be skipped rather than panicking.
func TestDecodeStringListSkipsNonStrings(t *testing.T) {
	got := decodeStringList([]interface{}{"malware", 123, nil, true, "identity"})
	want := []string{"malware", "identity"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("non-strings: got %v, want %v", got, want)
	}
}