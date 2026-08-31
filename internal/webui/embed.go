package webui

import (
	"embed"
	"io/fs"
)

//go:embed dist/*
var content embed.FS

func Assets() fs.FS {
	sub, err := fs.Sub(content, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}
