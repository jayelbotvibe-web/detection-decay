package main

import (
	"strings"
	"testing"

	"github.com/jayelbotvibe-web/detection-decay/internal/score"
)

func TestRenderHTMLEmpty(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("renderHTML panicked on empty results: %v", rec)
		}
	}()
	out := renderHTML("test.json", []score.Result{})
	if !strings.Contains(out, "no evidence rows") {
		t.Errorf("expected empty-state message in HTML output")
	}
	if !strings.Contains(out, "test.json") {
		t.Errorf("expected evidence path in HTML output")
	}
}

func TestRenderTextEmpty(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("renderText panicked on empty results: %v", rec)
		}
	}()
	out := renderText("test.json", []score.Result{})
	if !strings.Contains(out, "no evidence rows") {
		t.Errorf("expected empty-state message in text output")
	}
}

func TestRenderHTMLReportsEvidencePath(t *testing.T) {
	fp := 1.0
	res := score.ScoreAll([]score.Evidence{{
		Rule: "r.yml", State: "baseline", Liveness: "active",
		Volume: 10, BaselineVolume: 10,
		FieldPopulate: &fp, BaselineFieldPopulate: 1.0,
	}})
	out := renderHTML("lab-evidence.json", res)
	if !strings.Contains(out, "lab-evidence.json") {
		t.Errorf("expected evidence path in hero, hardcoded label regression?")
	}
	if strings.Contains(out, "purple-loop Windows Sysmon baseline") {
		t.Errorf("hardcoded lab label still present")
	}
}
