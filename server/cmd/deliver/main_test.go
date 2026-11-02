package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMarshalJSONKeepsAmpersand(t *testing.T) {
	rep := report{
		OK:      true,
		BaseURL: "http://127.0.0.1:8080",
		Code:    "AWQW",
		DBURL:   "postgres://user@127.0.0.1:5432/db?sslmode=disable&search_path=yanshu_core",
	}
	raw, err := marshalJSON(rep, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `\u0026`) {
		t.Fatalf("db_url ampersand was escaped: %s", raw)
	}
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	for _, k := range []string{"code", "package_id", "blob_dir", "db_url", "log_path"} {
		if _, ok := back[k]; !ok {
			t.Fatalf("missing key %q in stdout JSON", k)
		}
	}
}

func TestRedactDSNRemovesPassword(t *testing.T) {
	in := "postgres://yanshu_dev:s3cret@127.0.0.1:5432/yanshu_dev?sslmode=disable&search_path=yanshu_core"
	out := redactDSN(in)
	if strings.Contains(out, "s3cret") {
		t.Fatalf("password leaked: %s", out)
	}
	if !strings.Contains(out, "yanshu_dev@127.0.0.1:5432") {
		t.Fatalf("user/host lost: %s", out)
	}
	if !strings.Contains(out, "search_path=yanshu_core") {
		t.Fatalf("query params lost: %s", out)
	}
}
