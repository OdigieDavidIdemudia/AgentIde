//go:build windows

package main

import (
	"fmt"
	"hash/fnv"
	"image"
	"image/png"
	"os"
	"testing"
)

// The notification-area icon is drawn at runtime, so a mistake in the art
// produces an invisible or blank tray icon — exactly the failure this change
// exists to prevent. These tests run the real drawing code and assert on the
// pixels.
//
// They exercise drawTrayGlyph rather than buildTrayIcon because walk.Image is
// an opaque interface with no At(), so the wrapped result cannot be read back.

func TestTrayIconHasVisiblePixels(t *testing.T) {
	img := drawTrayGlyph(trayIconSize, trayAccent)

	if got := img.Bounds().Dx(); got != trayIconSize {
		t.Errorf("width = %d, want %d", got, trayIconSize)
	}
	if got := img.Bounds().Dy(); got != trayIconSize {
		t.Errorf("height = %d, want %d", got, trayIconSize)
	}

	if _, _, _, a := img.At(trayIconSize/2, trayIconSize/2).RGBA(); a == 0 {
		t.Fatal("centre is transparent — nothing would be visible in the notification area")
	}
}

// Corners must stay transparent so the icon does not read as a solid
// placeholder square.
func TestTrayIconCornersAreTransparent(t *testing.T) {
	img := drawTrayGlyph(trayIconSize, trayAccent)

	corners := [][2]int{
		{0, 0},
		{trayIconSize - 1, 0},
		{0, trayIconSize - 1},
		{trayIconSize - 1, trayIconSize - 1},
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
// which walk.NewBitmapFromImage would reject.
func TestTrayIconFallsBackOnInvalidSize(t *testing.T) {
	for _, size := range []int{0, -1} {
		img := drawTrayGlyph(size, trayAccent)
		if img.Bounds().Dx() != trayIconSize {
			t.Errorf("size %d fell back to %d, want %d", size, img.Bounds().Dx(), trayIconSize)
		}
	}
}

// Distinct state colours must produce distinct images, otherwise the state
// recolouring is a no-op and every state looks the same.
func TestStateColoursProduceDistinctIcons(t *testing.T) {
	build := func(state string) string {
		return fingerprint(drawTrayGlyph(trayIconSize, trayIconForState(state)))
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

// The wrap must not panic or error for any state.
func TestBuildTrayIconSucceedsForEveryState(t *testing.T) {
	for _, state := range []string{"connected", "connecting", "assessing", "disconnected", "error", "unknown"} {
		img, err := buildTrayIconWithBody(trayIconSize, trayIconForState(state))
		if err != nil {
			t.Errorf("state %q: %v", state, err)
			continue
		}
		if img == nil {
			t.Errorf("state %q produced a nil image", state)
		}
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
	t.Logf("wrote %s", path)
}
