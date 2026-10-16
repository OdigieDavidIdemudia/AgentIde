package main

import (
	"image"
	"image/color"
	"image/draw"

	"github.com/lxn/walk"
)

// The notification-area icon is composed at runtime rather than shipped as a
// .ico.
//
// There is no icon asset in the repository and the agent executable carries no
// icon resource either, so ExtractIcon-style approaches yield nothing — and a
// NotifyIcon with no image simply does not appear. Drawing it here also means
// the glyph always matches the dashboard theme instead of needing a design file
// kept in step with the CSS.
//
// The glyph is deliberately chunky: no anti-aliasing, no curves, hard edges.
// That matches both the 8-bit treatment on screen and how a tray icon reads at
// 16px, where anything subtle turns to mud.

const (
	trayIconSize = 32
)

// Palette for the drawn glyph. Vars, not consts: color.RGBA is a struct and
// structs are not constant expressions.
var (
	// ink is the near-black used for the outline, matching --ink in the
	// dashboard tokens.
	trayInk = color.RGBA{0x14, 0x14, 0x14, 0xFF}
	// mint is the product accent, matching --accent.
	trayAccent = color.RGBA{0x00, 0xD4, 0xAA, 0xFF}
	// red is the fail colour, matching --fail.
	trayFail = color.RGBA{0xFF, 0x4D, 0x4D, 0xFF}
)

// buildTrayIcon draws the AgentIde mark in its default accent colour.
func buildTrayIcon(size int) (walk.Image, error) {
	return buildTrayIconWithBody(size, trayAccent)
}

// buildTrayIconWithBody draws the shield with the supplied body colour, so a
// single asset serves every state.
func buildTrayIconWithBody(size int, body color.RGBA) (walk.Image, error) {
	return walk.NewBitmapFromImage(drawTrayGlyph(size, body))
}

// drawTrayGlyph renders the mark into a plain image.
//
// Split out from buildTrayIconWithBody because walk.Image is an opaque
// interface with no At(), so the result cannot be inspected. Keeping the drawing
// step pure is what makes the icon testable at all — and an icon that renders
// blank is invisible, which is the failure this whole change exists to prevent.
func drawTrayGlyph(size int, body color.RGBA) *image.RGBA {
	if size <= 0 {
		size = trayIconSize
	}

	img := image.NewRGBA(image.Rect(0, 0, size, size))

	// Scale the 16x16 design grid to the requested size so the glyph stays
	// proportional at other DPI buckets.
	u := size / 16
	if u < 1 {
		u = 1
	}

	// Transparent background — a solid square in the notification area looks
	// like a placeholder.
	draw.Draw(img, img.Bounds(), image.NewUniform(color.RGBA{}), image.Point{}, draw.Src)

	// 16x16 design grid, 1 = ink, 2 = accent, 3 = fail.
	// Shield silhouette with a block "A" cut into it.
	art := [16][16]byte{
		{0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0},
		{0, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 0},
		{1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1},
		{1, 2, 2, 1, 2, 2, 1, 2, 2, 1, 2, 2, 2, 2, 2, 1},
		{1, 2, 2, 1, 2, 2, 1, 2, 2, 1, 2, 2, 1, 2, 2, 1},
		{1, 2, 2, 1, 2, 2, 1, 2, 2, 1, 2, 2, 1, 2, 2, 1},
		{1, 2, 2, 1, 2, 2, 2, 2, 2, 1, 2, 2, 1, 2, 2, 1},
		{1, 2, 2, 1, 2, 2, 2, 2, 2, 1, 2, 2, 1, 2, 2, 1},
		{1, 2, 2, 1, 2, 2, 1, 2, 2, 1, 2, 2, 1, 2, 2, 1},
		{1, 2, 2, 1, 2, 2, 1, 2, 2, 1, 2, 2, 1, 2, 2, 1},
		{1, 2, 2, 2, 2, 2, 1, 2, 2, 1, 2, 2, 2, 2, 2, 1},
		{1, 1, 2, 2, 2, 2, 1, 2, 2, 1, 2, 2, 2, 2, 1, 1},
		{1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1},
		{0, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 0},
		{0, 0, 1, 1, 1, 2, 2, 2, 2, 2, 1, 1, 1, 0, 0, 0},
		{0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0},
	}

	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			var c color.RGBA
			switch art[y][x] {
			case 1:
				c = trayInk
			case 2:
				c = body
			case 3:
				c = trayFail
			default:
				continue // transparent
			}
			r := image.Rect(x*u, y*u, (x+1)*u, (y+1)*u)
			draw.Draw(img, r, image.NewUniform(c), image.Point{}, draw.Src)
		}
	}

	return img
}

// setTrayState recolours the icon to reflect agent state without needing a
// separate asset per state: the shield's body swaps between the accent mint and
// the fail red, and the outline stays ink so the glyph remains legible on any
// taskbar.
func trayIconForState(state string) color.RGBA {
	switch state {
	case "assessing":
		// Amber for work in progress; matches the dashboard's warn colour.
		return color.RGBA{0xF5, 0xA6, 0x23, 0xFF}
	case "disconnected", "error":
		return trayFail
	default:
		return trayAccent
	}
}
