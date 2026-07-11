//go:build windows

package file

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func writeFile(name string, data []byte, perm os.FileMode) error {
	dir, base := filepath.Split(name)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Uses a dotted-prefix pattern (".subnet.env.") that matches
	// what renameio generates internally on Unix.
	f, err := os.CreateTemp(dir, "."+base+".")
	if err != nil {
		return err
	}
	// On early exit (before the move), remove the temp file.
	// After a successful MoveFileEx the source path no longer exists,
	// so this becomes a harmless no-op.
	defer os.Remove(f.Name())

	if err := f.Chmod(perm); err != nil {
		return err
	}

	// 1. Write
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}

	// 2. Flush file contents
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}

	// 3. Close the file
	if err := f.Close(); err != nil {
		return err
	}

	src, err := windows.UTF16PtrFromString(f.Name())
	if err != nil {
		return err
	}

	dst, err := windows.UTF16PtrFromString(filepath.Join(dir, base))
	if err != nil {
		return err
	}

	// 4. Atomically swap the temp file into place.
	// MOVEFILE_REPLACE_EXISTING overwrites the destination if present.
	// MOVEFILE_WRITE_THROUGH requests the move and its metadata be flushed
	// to persistent storage before returning, as close to fsync(dir) as
	// Windows supports for this operation.
	return windows.MoveFileEx(
		src,
		dst,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH,
	)
}
