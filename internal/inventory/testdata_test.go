package inventory

import (
	"testing"
)

var invFixtureTree = map[string]string{
	"go.mod":                  "module example.com/app\n\ngo 1.25.0\n\nrequire golang.org/x/text v0.3.0\n",
	"testdata/go.mod":         "module example.com/fixture\n\ngo 1.25.0\n\nrequire golang.org/x/net v0.1.0\n",
	"testdata/Dockerfile.bad": "FROM golang AS build\nRUN go build ./...\n",
}

func TestTheWalksSkipTestdataUnlessAsked(t *testing.T) {
	root := invTree(t, invFixtureTree)
	for _, o := range []Options{{}, {Testdata: true}} {
		pkgs, _, err := Scan(root, o)
		if err != nil {
			t.Fatal(err)
		}
		_, gaps := BuildLines(root, o)
		read := invHas(pkgs, "golang.org/x/net", "0.1.0")
		if read != o.Testdata || (len(gaps) > 0) != o.Testdata {
			t.Fatalf("%+v: fixture lockfile read = %v, Dockerfile gaps = %v", o, read, gaps)
		}
	}
}
