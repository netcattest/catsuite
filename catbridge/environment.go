package main

import "os"

func minimalEnvironment() []string {
	result := []string{}
	for _, name := range []string{"SystemRoot", "WINDIR", "TEMP", "TMP", "PATH", "LANG", "LC_ALL"} {
		if value, ok := os.LookupEnv(name); ok {
			result = append(result, name+"="+value)
		}
	}
	return result
}
