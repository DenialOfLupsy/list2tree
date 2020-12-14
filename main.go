package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

type process struct {
	pid  string
	ppid string
	info string
}

type mapValue struct {
	pid       string
	hasParent bool
	info      string
	children  []string
}

func main() {

	pslist, err := parse(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}

	/*pslist := []process{
		{4, 0, "services.exe"},
		{72, 4, "svchost.exe"},
		{128, 4, "svchost.exe"},
		{512, 4, "svchost.exe"},
		{3321, 512, "ShellExperienceHost.exe"},
		{8724, 512, "RuntimeBroker.exe"},
		{724, 608, "onedrive.exe"},
		{777, 724, "exploit.exe"},
		{812, 608, "powershell.exe"},
	}*/
	printRoots(parseList(pslist))
}

func parseList(pslist []process) map[string]mapValue {
	psmap := map[string]mapValue{}

	for _, proc := range pslist {
		parent := psmap[proc.ppid]
		parent.children = append(parent.children, proc.pid)
		psmap[proc.ppid] = parent
		child := psmap[proc.pid]
		child.hasParent = true
		child.info = proc.info
		child.pid = proc.pid
		psmap[proc.pid] = child
	}
	return psmap
}

func printRoots(psmap map[string]mapValue) {
	for id, mv := range psmap {
		if mv.hasParent {
			continue
		}
		printTree(psmap, id, 0)
	}
}

func printTree(psmap map[string]mapValue, pid string, depth int) {
	fmt.Printf("%s%s:\t%s\n", strings.Repeat("  ", depth), pid, psmap[pid].info)
	for _, c := range psmap[pid].children {
		printTree(psmap, c, depth+1)
	}
}

func parse(input io.Reader) ([]process, error) {
	r := csv.NewReader(input)
	r.Comma = '\t'
	records, err := r.ReadAll()

	if err != nil {
		return nil, err
	}

	allProcesses := []process{}

	for _, line := range records {
		p := process{line[0], line[1], strings.Join(line[2:], "|")}
		allProcesses = append(allProcesses, p)
	}

	return allProcesses, nil
}
