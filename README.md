# gen-fuzz
gen-fuzz is a library to automatically generate fuzzing file(s) for target function(s).

Import with `import "github.com/yanzhoupan/gen-fuzz"`

FLAGS:

| Flag | Explanation                                                                      |  
|------|----------------------------------------------------------------------------------|
| -dir | The dir of the package that contains the target function, set to `./` by default | 
| -f   | The name of the target function. For example `Add`                               | 
| -o   | The name of the output file. For example `my_fuzz`                               |

Example command: `gen-fuzz -dir=./ -f=Add -o=fuzz`

NOTE:
1. Not all inputs should be generated by gofuzz, let user to define some of them
2. Also need to let users take care of the return value of the fuzz function

TODO:
1. Support generating fuzz function for multiple target functions (given function names/functions with pattern/all functions).(/fuzz1/fuzz.go, /fuzz2/fuzz.go, fuzz1...N are separate fuzz units for different target functions)
2. Add flag to automatically run go-fuzz on the generated file (need to go-fuzz-build first)
3. Automatically generate unit test from the inputs that made the function crush. (most likely there are already unit tests)
