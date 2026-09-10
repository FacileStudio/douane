package inventory

import (
	"encoding/json"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
)

// splitNameVersion splits a bun descriptor such as "@scope/pkg@1.2.3" on the
// last "@", so scoped package names survive intact.
func splitNameVersion(d string) (string, string) {
	i := strings.LastIndex(d, "@")
	if i <= 0 {
		return d, ""
	}
	return d[:i], d[i+1:]
}

// bunWorkspace is one block of the workspaces map, keyed by workspace path.
type bunWorkspace struct {
	Name            string            `json:"name"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// parseBunLock reads bun's text lockfile. Each package entry is an array whose
// first element is the resolved "name@version" descriptor and whose third
// element carries the package's own dependency map.
func parseBunLock(_ string, data []byte) ([]finding.Package, []finding.Gap, error) {
	var lock struct {
		Workspaces map[string]bunWorkspace      `json:"workspaces"`
		Packages   map[string][]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(stripJSONC(data), &lock); err != nil {
		return nil, nil, err
	}
	graph := bunGraph(lock.Workspaces, lock.Packages)
	prod, dev := bunClosures(lock.Workspaces, graph)
	var pkgs []finding.Package
	for _, entry := range lock.Packages {
		if len(entry) == 0 {
			continue
		}
		var descriptor string
		if err := json.Unmarshal(entry[0], &descriptor); err != nil {
			continue
		}
		name, version := splitNameVersion(descriptor)
		if version == "" || strings.Contains(version, ":") {
			continue
		}
		pkgs = append(pkgs, finding.Package{
			Name: name, Ecosystem: "npm", Version: version,
			Scope: bunScope(prod, dev, name),
		})
	}
	return pkgs, nil, nil
}

// bunGraph builds the name-level dependency graph: a node's neighbours are the
// union of its workspace block's dependency keys, which is where workspace:*
// links resolve, and its packages entry's own dependency map.
func bunGraph(workspaces map[string]bunWorkspace, packages map[string][]json.RawMessage) map[string]map[string]bool {
	adj := make(map[string]map[string]bool)
	for _, ws := range workspaces {
		addDeps(adj, ws.Name, ws.Dependencies)
		addDeps(adj, ws.Name, ws.DevDependencies)
	}
	for name, entry := range packages {
		if len(entry) < 3 {
			continue
		}
		var deps struct {
			Dependencies map[string]string `json:"dependencies"`
		}
		if err := json.Unmarshal(entry[2], &deps); err != nil {
			continue
		}
		addDeps(adj, name, deps.Dependencies)
	}
	return adj
}

// addDeps records an edge from node to every name in deps.
func addDeps(adj map[string]map[string]bool, node string, deps map[string]string) {
	if node == "" || len(deps) == 0 {
		return
	}
	neighbours := adj[node]
	if neighbours == nil {
		neighbours = make(map[string]bool)
		adj[node] = neighbours
	}
	for name := range deps {
		neighbours[name] = true
	}
}

// bunClosures splits the graph's reachable names into prod and dev. Prod is
// every name reachable from some workspace dependency, dev every name
// reachable from some devDependency. A lockfile with no workspaces key has no
// seeds, so both closures stay empty and everything defaults to prod.
func bunClosures(workspaces map[string]bunWorkspace, adj map[string]map[string]bool) (map[string]bool, map[string]bool) {
	if len(workspaces) == 0 {
		return map[string]bool{}, map[string]bool{}
	}
	var prodSeeds, devSeeds []string
	for _, ws := range workspaces {
		for name := range ws.Dependencies {
			prodSeeds = append(prodSeeds, name)
		}
		for name := range ws.DevDependencies {
			devSeeds = append(devSeeds, name)
		}
	}
	return bunReachable(prodSeeds, adj), bunReachable(devSeeds, adj)
}

// bunReachable returns the seeds and every name reachable from them.
func bunReachable(seeds []string, adj map[string]map[string]bool) map[string]bool {
	seen := make(map[string]bool)
	queue := make([]string, 0, len(seeds))
	for _, s := range seeds {
		if !seen[s] {
			seen[s] = true
			queue = append(queue, s)
		}
	}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		for next := range adj[node] {
			if !seen[next] {
				seen[next] = true
				queue = append(queue, next)
			}
		}
	}
	return seen
}

// bunScope marks a package dev only when it is reachable from a devDependency
// and from no dependency. A name in both closures is prod, and so is a name in
// neither: guessing dev would hide a real finding, so unknown defaults to prod.
func bunScope(prod, dev map[string]bool, name string) finding.Scope {
	if dev[name] && !prod[name] {
		return finding.ScopeDev
	}
	return finding.ScopeProd
}
