package main

import (
	"strings"
	"testing"

	"github.com/jayelbotvibe-web/detection-decay/internal/score"
)

func TestRenderHTMLEmpty(t *testing.T) {
	html := renderHTML(nil, "test.json")
	if !strings.Contains(html, "no evidence rows") {
		t.Errorf("expected 'no evidence rows' in empty HTML render, got: %s", html[:200])
	}
}

func TestRenderTextEmpty(t *testing.T) {
	txt := renderText(nil, "test.json")
	if !strings.Contains(txt, "no evidence rows") {
		t.Errorf("expected 'no evidence rows' in empty text render, got: %s", txt[:200])
	}
}

func TestRenderHTMLEmptyNilSlice(t *testing.T) {
	html := renderHTML([]score.Result{}, "test.json")
	if !strings.Contains(html, "no evidence rows") {
		t.Errorf("expected 'no evidence rows' for empty slice, got: %s", html[:200])
	}
}

func TestRenderTextEmptyNilSlice(t *testing.T) {
	txt := renderText([]score.Result{}, "test.json")
	if !strings.Contains(txt, "no evidence rows") {
		t.Errorf("expected 'no evidence rows' for empty slice, got: %s", txt[:200])
	}
}
