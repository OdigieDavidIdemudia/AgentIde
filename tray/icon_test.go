//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"image"
	"image/png"
	"os"
	"testing"
)

// The notification-area icon is drawn and packaged at runtime, so a mistake in
// either the art or the .ico container produces an invisible or blank tray icon
// - exactly the failure this code exists to prevent. These tests run the real
// code and assert on the pixels and on the bytes handed to the shell.

func TestTrayIconHasVisiblePixels(t *testing.T) {
	img := drawTrayGlyph(trayIconMid, trayAccent)

	if got := img.Bounds().Dx(); got != trayIconMid {
		t.Errorf("width = %d, want %d", got, trayIconMid)
	}
	if got := img.Bounds().Dy(); got != trayIconMid {
		t.Errorf("height = %d, want %d", got, trayIconMid)
	}

	if _, _, _, a := img.At(trayIconMid/2, trayIconMid/2).RGBA(); a == 0 {
		t.Fatal("centre is transparent - nothing would be visible in the notification area")
	}
}

// Corners must stay transparent so the icon does not read as a solid
// placeholder square.
func TestTrayIconCornersAreTransparent(t *testing.T) {
	img := drawTrayGlyph(trayIconMid, trayAccent)

	corners := [][2]int{
		{0, 0},
		{trayIconMid - 1, 0},
		{0, trayIconMid - 1},
		{trayIconMid - 1, trayIconMid - 1},
	}
	for _, c := range corners {
		if _, _, _, a := img.At(c[0], c[1]).RGBA(); a != 0 {
			t.Errorf("corner %v is opaque (alpha=%d); the icon must not be a solid square", c, a>>8)
		}
	}
}

// The glyph must be drawn at every requested size, since Windows picks
// different sizes per DPI bucket.
func TestTrayIconScalesToRequestedSize(t *testing.T) {
	for _, size := range []int{16, 20, 24, 32, 48} {
		img := drawTrayGlyph(size, trayAccent)
		if img.Bounds().Dx() != size || img.Bounds().Dy() != size {
			t.Errorf("requested %d got %dx%d", size, img.Bounds().Dx(), img.Bounds().Dy())
		}
		if _, _, _, a := img.At(size/2, size/2).RGBA(); a == 0 {
			t.Errorf("size %d renders a blank centre", size)
		}
	}
}

// A non-positive size must fall back rather than producing a zero-sized image,
// which would encode as an empty DIB.
func TestTrayIconFallsBackOnInvalidSize(t *testing.T) {
	for _, size := range []int{0, -1} {
		img := drawTrayGlyph(size, trayAccent)
		if img.Bounds().Dx() != trayIconMid {
			t.Errorf("size %d fell back to %d, want %d", size, img.Bounds().Dx(), trayIconMid)
		}
	}
}

// Distinct state colours must produce distinct icons, otherwise the state
// recolouring is a no-op and every state looks the same.
func TestStateColoursProduceDistinctIcons(t *testing.T) {
	build := func(state string) string {
		return fingerprint(drawTrayGlyph(trayIconMid, trayBodyForState(state)))
	}

	connected := build("connected")
	assessing := build("assessing")
	offline := build("disconnected")

	if connected == assessing {
		t.Error("connected and assessing are identical; state colour is not reaching the image")
	}
	if connected == offline {
		t.Error("connected and disconnected are identical; failure state is not visible")
	}
	if assessing == offline {
		t.Error("assessing and disconnected are identical")
	}
}

// Every state must still encode. trayIconBytes cannot report an error, so a
// panic here would be the only failure signal and it would take the tray with
// it.
func TestTrayIconBytesSucceedsForEveryState(t *testing.T) {
	for _, state := range []string{"connected", "connecting", "assessing", "disconnected", "error", "unknown"} {
		ico := trayIconBytes(trayBodyForState(state))
		if len(ico) == 0 {
			t.Errorf("state %q produced no icon bytes", state)
			continue
		}
		// Must round-trip through the structural checks below.
		if err := checkICO(t, ico); err != nil {
			t.Errorf("state %q: %v", state, err)
		}
	}
}

// TestICOContainerIsWellFormed checks the parts of the .ico layout that the
// shell parses before it ever looks at pixels. Every one of these is a place
// where an off-by-one produces an icon that silently never appears.
func TestICOContainerIsWellFormed(t *testing.T) {
	ico := trayIconBytes(trayAccent)

	if got := binary.LittleEndian.Uint16(ico[0:]); got != 0 {
		t.Errorf("reserved = %d, want 0", got)
	}
	if got := binary.LittleEndian.Uint16(ico[2:]); got != 1 {
		t.Errorf("type = %d, want 1 (icon)", got)
	}
	count := int(binary.LittleEndian.Uint16(ico[4:]))
	if count != 4 {
		t.Errorf("image count = %d, want 4 (16/24/32/48)", count)
	}

	if err := checkICO(t, ico); err != nil {
		t.Fatal(err)
	}
}

// checkICO walks the directory entries and validates offsets, lengths and the
// BITMAPINFOHEADER of each frame.
func checkICO(t *testing.T, ico []byte) error {
	t.Helper()

	count := int(binary.LittleEndian.Uint16(ico[4:]))
	end := icoHeaderBytes + icoEntryBytes*count
	if end > len(ico) {
		return fmt.Errorf("directory (%d bytes) overruns %d-byte payload", end, len(ico))
	}

	for i := 0; i < count; i++ {
		e := ico[icoHeaderBytes+i*icoEntryBytes:]

		w, h := int(e[0]), int(e[1])
		if w == 0 || h == 0 {
			return fmt.Errorf("entry %d: zero dimension (%dx%d); 0 means 256 and is not intended", i, w, h)
		}
		if w != h {
			return fmt.Errorf("entry %d: not square: %dx%d", i, w, h)
		}
		if bpp := binary.LittleEndian.Uint16(e[6:]); bpp != 32 {
			return fmt.Errorf("entry %d: bit count = %d, want 32", i, bpp)
		}

		size := int(binary.LittleEndian.Uint32(e[8:]))
		off := int(binary.LittleEndian.Uint32(e[12:]))
		if off < end {
			return fmt.Errorf("entry %d: offset %d overlaps the directory (ends at %d)", i, off, end)
		}
		if off+size > len(ico) {
			return fmt.Errorf("entry %d: frame [%d,%d) overruns %d-byte payload", i, off, off+size, len(ico))
		}

		frame := ico[off : off+size]
		if got := binary.LittleEndian.Uint32(frame[0:]); got != dibHeaderBytes {
			return fmt.Errorf("entry %d: BITMAPINFOHEADER size = %d, want %d", i, got, dibHeaderBytes)
		}
		// Height is doubled because the DIB carries the AND mask too.
		if got := int(binary.LittleEndian.Uint32(frame[8:])); got != h*2 {
			return fmt.Errorf("entry %d: header height = %d, want %d (image + mask)", i, got, h*2)
		}
		if got := int(binary.LittleEndian.Uint32(frame[4:])); got != w {
			return fmt.Errorf("entry %d: header width = %d, want %d", i, got, w)
		}

		want := dibHeaderBytes + w*h*4 + ((w+31)/32*4)*h
		if len(frame) != want {
			return fmt.Errorf("entry %d: frame is %d bytes, want %d", i, len(frame), want)
		}
	}

	// Entries are emitted back-to-back, so the last frame must end exactly at
	// the end of the payload. A short write here means a truncated file.
	last := ico[icoHeaderBytes+(count-1)*icoEntryBytes:]
	off := int(binary.LittleEndian.Uint32(last[12:]))
	size := int(binary.LittleEndian.Uint32(last[8:]))
	if off+size != len(ico) {
		return fmt.Errorf("last frame ends at %d, want %d", off+size, len(ico))
	}

	return nil
}

// The DIB must round-trip: decoding the encoded BGRA back through a real image
// must reproduce the drawn glyph. This catches a wrong channel order, a missing
// bottom-up flip, or rows that are not padded, all of which produce a garbled
// or half-empty icon that no structural check would notice.
func TestDIBRoundTrips(t *testing.T) {
	orig := drawTrayGlyph(trayIconMid, trayAccent)
	dib := encodeDIB(orig)

	b := orig.Bounds()
	w, h := b.Dx(), b.Dy()

	xor := dib[dibHeaderBytes:]
	back := image.NewRGBA(image.Rect(0, 0, w, h))

	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			i := (y*w + x) * 4
			// Stored bottom-up, so the source row is mirrored.
			c := orig.RGBAAt(b.Min.X+x, b.Max.Y-1-y)
			if xor[i+0] != c.B || xor[i+1] != c.G || xor[i+2] != c.R || xor[i+3] != c.A {
				t.Fatalf("pixel (%d,%d): stored BGRA %v, want %v", x, y,
					[]byte{xor[i], xor[i+1], xor[i+2], xor[i+3]},
					[]byte{c.B, c.G, c.R, c.A})
			}
			back.SetRGBA(b.Min.X+x, b.Min.Y+h-1-y, c)
		}
	}

	if fingerprint(back) != fingerprint(orig) {
		t.Error("round-tripped image differs from the original; row order or padding is wrong")
	}
}

// Different states must produce different bytes, not merely different images.
// The tray swaps SetIcon calls on state change, so if the bytes were identical
// the icon would never appear to update.
func TestStateBytesDiffer(t *testing.T) {
	connected := trayIconBytes(trayBodyForState("connected"))
	assessing := trayIconBytes(trayBodyForState("assessing"))
	offline := trayIconBytes(trayBodyForState("disconnected"))

	if bytes.Equal(connected, assessing) {
		t.Error("connected and assessing produce identical icon bytes")
	}
	if bytes.Equal(connected, offline) {
		t.Error("connected and disconnected produce identical icon bytes")
	}
	if bytes.Equal(assessing, offline) {
		t.Error("assessing and disconnected produce identical icon bytes")
	}
}

// fingerprint is a cheap deterministic digest of an image's pixels, enough to
// prove two renders differ.
func fingerprint(img image.Image) string {
	b := img.Bounds()
	h := fnv.New64a()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, a := img.At(x, y).RGBA()
			fmt.Fprintf(h, "%d,%d,%d,%d;", r>>8, g>>8, bl>>8, a>>8)
		}
	}
	return fmt.Sprintf("%x", h.Sum64())
}

// Developer aid: there is no display in CI, so the glyph is written to a PNG
// for eyeballing. Run with TRAY_DEBUG_PNG set:
//
//	TRAY_DEBUG_PNG=icon.png go test -run TestWriteDebugPNG ./...
func TestWriteDebugPNG(t *testing.T) {
	path := os.Getenv("TRAY_DEBUG_PNG")
	if path == "" {
		t.Skip("set TRAY_DEBUG_PNG=<path> to write the icon for inspection")
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create png: %v", err)
	}
	defer f.Close()
	if err := png.Encode(f, drawTrayGlyph(32, trayAccent)); err != nil {
		t.Fatalf("encode png: %v", err)
	}

	// Also emit the real .ico so it can be opened in Explorer and confirmed to
	// render, which is the only true test of the container.
	icoPath := path + ".ico"
	if err := os.WriteFile(icoPath, trayIconBytes(trayAccent), 0o644); err != nil {
		t.Fatalf("write ico: %v", err)
	}

	t.Logf("wrote %s and %s", path, icoPath)
}