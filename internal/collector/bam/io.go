package bam

import "os"

// readFile se aísla como variable para poder sustituirla en tests si hace falta.
var readFile = os.ReadFile
