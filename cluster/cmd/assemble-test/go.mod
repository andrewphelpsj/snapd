module assemble

go 1.24.5

replace github.com/snapcore/snapd => ../../../

require (
	github.com/snapcore/snapd v0.0.0-00010101000000-000000000000
	golang.org/x/sync v0.15.0
)

require (
	golang.org/x/net v0.21.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
	golang.org/x/time v0.10.0 // indirect
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
