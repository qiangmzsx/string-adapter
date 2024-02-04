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
package main

import (
	"fmt"

	scas "github.com/qiangmzsx/string-adapter/v2"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
)

func main() {

	modelText := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _
g2 = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && g2(r.obj, p.obj) && r.act == p.act`

	m := model.NewModel()

	m.LoadModelFromText(modelText)

	line := `
p, alice, data1, read
p, bob, data2, write
p, data_group_admin, data_group, write

g, alice, data_group_admin
g2, data1, data_group
g2, data2, data_group
`
	sa := scas.NewAdapter(line)

	// Initialize a Gorm adapter and use it in a Casbin enforcer:
	// The adapter will use the MySQL database named "casbin".
	// If it doesn't exist, the adapter will create it automatically.
	// You can also use an already existing gorm instance with gormadapter.NewAdapterByDB(gormInstance)
	//a, _ := gormadapter.NewAdapter("mysql", "mysql_username:mysql_password@tcp(127.0.0.1:3306)/") // Your driver and data source.
	//	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)
	e, _ := casbin.NewEnforcer(m, sa)

	// Or you can use an existing DB "abc" like this:
	// The adapter will use the table named "casbin_rule".
	// If it doesn't exist, the adapter will create it automatically.
	// a := gormadapter.NewAdapter("mysql", "mysql_username:mysql_password@tcp(127.0.0.1:3306)/abc", true)

	// Load the policy from DB.
	e.LoadPolicy()

	// Check the permission.
	if res, _ := e.Enforce("alice", "data1", "read"); res {
		fmt.Println("permitted")
	} else {
		fmt.Println("rejected")
	}

	// Modify the policy.
	// e.AddPolicy(...)
	// e.RemovePolicy(...)

	// Save the policy back to DB.
	e.SavePolicy()
}

```
