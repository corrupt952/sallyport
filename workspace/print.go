package workspace

import "fmt"

func Info(format string, a ...any) { fmt.Printf("  [ .. ] "+format+"\n", a...) }
func Ok(format string, a ...any)   { fmt.Printf("  [ OK ] "+format+"\n", a...) }
func Warn(format string, a ...any) { fmt.Printf("  [ !! ] "+format+"\n", a...) }
