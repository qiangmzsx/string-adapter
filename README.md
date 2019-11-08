# string-adapter
string  adapter for Casbin https://github.com/casbin/casbin 

# Installation

go get github.com/qiangmzsx/string-adapter



# Simple Example
## casbin v1
```go  
package main

import (
	"fmt"
	"github.com/casbin/casbin"
	scas "github.com/qiangmzsx/string-adapter"
	"github.com/casbin/casbin/file-adapter"
)

func main() {
	KeyMatchRbac()
	//StringRbac()
	//UserRbac()
}

func KeyMatchRbac() {
	conf := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _ , _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub)  && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)
`
	line := `
p, alice, /alice_data/*, (GET)|(POST)
p, alice, /alice_data/resource1, POST
p, data_group_admin, /admin/*, POST
p, data_group_admin, /bob_data/*, POST
g, alice, data_group_admin
`
	sa := scas.NewAdapter(line)
	e := casbin.NewEnforcer(casbin.NewModel(conf), sa)
	sub := "alice"
	obj := "/alice_data1/login"
	act := "POST"
	if e.Enforce(sub, obj, act) == true {
		fmt.Println("**YES**")
	} else {
		fmt.Println("--NO--")
	}
}

func StringRbac() {
	conf := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _ , _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`
	line := `
p, alice, data1, read
p, data_group_admin, data3, read
p, data_group_admin, data3, write
g, alice, data_group_admin
`
	sa := scas.NewAdapter(line)
	e := casbin.NewEnforcer(casbin.NewModel(conf), sa)
	sub := "alice" // the user that wants to access a resource.
	obj := "data1" // the resource that is going to be accessed.
	act := "write" // the operation that the user performs on the resource.
	if e.Enforce(sub, obj, act) == true {
		fmt.Println("**YES**")
	} else {
		fmt.Println("--NO--")
	}
}
```

## casbin v2
```go

```
