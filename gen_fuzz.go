package main

import (
	"flag"
	"fmt"
	"go/types"
	"golang.org/x/tools/go/packages"
	"os"
	"reflect"
	"strings"
	"text/template"
)

var (
	flagPkg      = flag.String("dir", ".", "Directory of the package")
	flagFuncName = flag.String("functions", "targetFunction1, targetFunction2", "Target function to do fuzz on")
)

var fuzzSrc = template.Must(template.New("Fuzz").Parse(`// +build gofuzz

package {{.pkg}}

import (
	fuzz "github.com/google/gofuzz"
)

func Fuzz(data []byte) int {
	{{- range $i, $v := .inputs}}
	var {{index $v 0}} {{index $v 1}}
	{{- end}}

	// Using github.com/google/gofuzz to generate the function input for function "{{.funcName}}"
	// NOTE: gouzz only support basic types, you can modify this part if you want to define some inputs by yourself
	f := fuzz.NewFromGoFuzz(data).NilChance(0)
	{{- range $i, $v := .inputs}}
	f.Fuzz(&{{index $v 0}})
	{{- end}}

	// Calling the target function "{{.funcName}}"
	{{.pkg}}.{{.funcName}}(
	{{- $first := true}}
	{{- range $i, $v := .inputs}}
	{{- if $first}}
		{{- $first = false}}
	{{- else -}}
		,
	{{- end}}
	{{- index $v 0}}
	{{- end}})

	// NOTE: you can return 1 if the fuzzer should increase priority of the given input during subsequent fuzzing, 
	// or -1 if the input must not be added to corpus even if gives new coverage (https://github.com/dvyukov/go-fuzz)
	return 0
}
`))

// Context holds state for a gen-fuzz run. (This is copied from go-fuzz/go-fuzz-build/main.go)
type Context struct {
	targetFuncObj types.Object
	inputs        [][]string
	pkgs          []*packages.Package // type-checked root packages

	std    map[string]bool // set of packages in the standard library
	ignore map[string]bool // set of packages to ignore during instrumentation

	allFuncs []string // all fuzz functions found in package

	workdir string
	GOROOT  string
	GOPATH  string
}

func basePackagesConfig() *packages.Config {
	cfg := new(packages.Config)
	cfg.Env = os.Environ()
	return cfg
}

func (c *Context) failf(str string, args ...interface{}) {
	//c.cleanup()
	_, err := fmt.Fprintf(os.Stderr, str+"\n", args...)
	if err != nil {
		return
	}
	os.Exit(1)
}

func (c *Context) writeFile(fileName string, t *template.Template, varMap map[string]interface{}) {
	f, err := os.Create(fileName)
	if err != nil {
		c.failf("create file err: ", err)
		return
	}
	if err := t.Execute(f, varMap); err != nil {
		c.failf("could not execute template: %v", err)
	}
	fmt.Printf("successfully generated go-fuzz code into file: %v\n", fileName)
}

func (c *Context) loadFuncObj(pkg string, funcName string) {
	// Resolve pkg.
	cfg := basePackagesConfig()
	cfg.Mode = packages.NeedName | packages.NeedTypes
	pkgs, err := packages.Load(cfg, pkg)
	if err != nil {
		c.failf("could not resolve package %q: %v", pkg, err)
	}
	if len(pkgs) == 0 {
		c.failf("didn't find any packages under the given dir %q...", pkg)
	}
	if len(pkgs) != 1 {
		paths := make([]string, len(pkgs))
		for i, p := range pkgs {
			paths[i] = p.PkgPath
		}
		c.failf("cannot build multiple packages, but %q resolved to: %v", pkg, strings.Join(paths, ", "))
	}
	if pkgs[0].Name == "main" {
		c.failf("cannot fuzz main package")
	}

	// Get the target function object
	targetFuncObj := pkgs[0].Types.Scope().Lookup(funcName)
	if targetFuncObj == nil {
		c.failf("didn't find function %v under package %v", funcName, pkg)
	}
	if targetFuncObjType := reflect.TypeOf(targetFuncObj).Elem(); targetFuncObjType != reflect.TypeOf(types.Func{}) {
		c.failf("the kind of %v should be a func, but resolved to %v", funcName, targetFuncObjType)
	}
	c.targetFuncObj = targetFuncObj
}

func (c *Context) parseFunc() {
	// Parse the target function's input and store a [][]string containing name and type
	// such as {{"var1", "string"}, {"var2", "int32"}}
	funcInfo := c.targetFuncObj.Type().String() // such as func(var1 string, var2 int32)
	inputStr := ""
	i := strings.Index(funcInfo, "(")
	if i >= 0 {
		j := strings.Index(funcInfo[i:], ")")
		if j >= 0 {
			inputStr = funcInfo[i+1 : i+j]
		}
	}
	if inputStr == "" {
		c.failf("no inputStr found from the given function info: %v", funcInfo)
	}
	inputs := strings.Split(inputStr, ",")

	for _, input := range inputs {
		inputVar := strings.Split(strings.TrimSpace(input), " ")
		c.inputs = append(c.inputs, []string{inputVar[0], inputVar[1]})
	}
}

func main() {
	// Example command: gen-fuzz -dir=./ -f=Add -o=fuzz
	flag.Parse()
	pkgDir := *flagPkg
	funcNames := *flagFuncName

	funcNameList := strings.Split(funcNames, ",")
	fmt.Println("funcNameList: ", funcNameList)

	// Load and parse the target function
	c := new(Context)
	for _, funcName := range funcNameList {
		fmt.Println("================")
		funcName = strings.TrimSpace(funcName)
		c.loadFuncObj(pkgDir, funcName)
		c.parseFunc()
		pkgName := c.targetFuncObj.Pkg().Name()
		fmt.Printf("package name: %v\nfuncName: %v\ninputs: %v\n", pkgName, funcName, c.inputs)

		// Generate fuzz function to the output file (use fuzz_funcName/fuzz.go)
		fmt.Printf("generating fuzz functions...\n")
		pathName := strings.TrimRight(pkgDir, "/") + "/fuzz_" + funcName
		err := os.MkdirAll(pathName, os.ModePerm)
		if err != nil {
			c.failf("err when creating target path %q, err massage is %s", pathName, err)
		}
		varMap := map[string]interface{}{"pkg": pkgName, "funcName": funcName, "inputs": c.inputs}
		outputTemplate := fuzzSrc
		c.writeFile(pathName+"/fuzz.go", outputTemplate, varMap)
	}
}
