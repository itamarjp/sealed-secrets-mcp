package main

import (
	"context"
	"strings"
	"testing"
)

func TestRotationDefaultDeny(t *testing.T) {
	tool, _ := fakeCluster(t)
	target := target{Namespace: "apps", Name: "db"}
	if tool.rotateAllowed(target) {
		t.Fatal("rotation enabled by default")
	}
	_, _, err := tool.rotate(context.Background(), nil, rotateInput{
		target: target,
		Keys: []keySpec{{Key: "PASSWORD", Encoding: "hex", Length: 32}},
	})
	if err == nil || !strings.Contains(err.Error(), "OAuth") {
		t.Fatalf("unverified rotation not refused: %v", err)
	}
}

func TestRotationUsesExactResourceTarget(t *testing.T) {
	tool, _ := fakeCluster(t)
	tool.allowedTargets = []target{{Namespace: "apps", Name: "db"}}
	tool.rotateTargets = []target{{Namespace: "apps", Name: "db"}}
	if !tool.rotateAllowed(target{Namespace: "apps", Name: "db"}) {
		t.Fatal("exact rotation target rejected")
	}
	for _, denied := range []target{
		{Namespace: "apps", Name: "db2"},
		{Namespace: "other", Name: "db"},
		{Namespace: "apps", Name: "db-extra"},
	} {
		if tool.rotateAllowed(denied) || tool.targetAllowed(denied) {
			t.Fatalf("non-exact resource accepted: %+v", denied)
		}
	}
}

func TestGeneratedRotationMaterialNoNewline(t *testing.T) {
	v, err := randomValue(keySpec{Key: "password", Encoding: "hex", Length: 32})
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 64 {
		t.Fatalf("expected 64 bytes, got %d", len(v))
	}
	if strings.ContainsAny(string(v), "\r\n") {
		t.Fatal("credential includes newline")
	}
}
