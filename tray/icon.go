package main

// The notification-area icon is composed at runtime rather than shipped as a
// .ico asset.
//
// There is no icon file in the repository and the agent executable carries no
// icon resource either, so ExtractIcon-style approaches yield nothing - and a
// tray icon with no image simply does not appear. Drawing it here also keeps the
// glyph in step with the dashboard theme without needing a design file that has
// to be updated whenever the CSS changes.
//
// The glyph is deliberately chunky: no anti-aliasing, no curves, hard edges. That
// matches the 8-bit treatment on screen and how a tray icon reads at 16px, where
// anything subtle turns to mud.
//
// Output is a real .ico container holding 32-bit BGRA DIB entries at several
// sizes, because that is what systray's SetIcon loads. Go's standard library
// has no ICO encoder, so the container is assembled here: it is a small,
// fixed-layout format and writing it directly is clearer than pulling in a
// dependency for forty lines.

import (
	"encoding/binary"
	"image"
	"image/color"
	"image/draw"
)

const (
	// trayIconSizes are the frame sizes embedded in the ICO. Windows picks the
	// closest match for the taskbar's current DPI, so covering 16 through 48
	// avoids upscaling a single 32px frame into a blur on high-DPI displays.
	// 24 is included because 150% scaling is a common taskbar size and would
	// otherwise fall back to the 16px frame.
	trayIconSmall = 16
	trayIconMd    = 24
	trayIconMid   = 32
	trayIconLarge = 48

	// icoHeaderBytes is ICONDIR: reserved, type=1 (icon), image count.
	icoHeaderBytes = 6
	// icoEntryBytes is ICONDIRENTRY.
	icoEntryBytes = 16
	// dibHeaderBytes is BITMAPINFOHEADER.
	dibHeaderBytes = 40
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
	// amber is the in-progress colour, matching --warn.
	trayWarn = color.RGBA{0xF5, 0xA6, 0x23, 0xFF}
)

// trayIconBytes builds the .ico payload for the supplied body colour.
//
// Multiple sizes are embedded because SetIcon hands the bytes to the shell,
// which loads them with LoadImage(IMAGE_ICON) and picks by DPI. Embedding a
// single size would mean a 16px taskbar gets a downscaled 48px frame and a
// 200% display gets an upscaled one; both look wrong and the 16px case is the
// common one.
func trayIconBytes(body color.RGBA) []byte {
	sizes := []int{trayIconSmall, trayIconMd, trayIconMid, trayIconLarge}

	frames := make([][]byte, len(sizes))
	for i, s := range sizes {
		frames[i] = encodeDIB(drawTrayGlyph(s, body))
	}

	out := make([]byte, icoHeaderBytes+icoEntryBytes*len(frames))
	binary.LittleEndian.PutUint16(out[0:], 0) // reserved
	binary.LittleEndian.PutUint16(out[2:], 1) // 1 = icon
	binary.LittleEndian.PutUint16(out[4:], uint16(len(frames)))

	offset := uint32(len(out))
	for i, frame := range frames {
		e := out[icoHeaderBytes+i*icoEntryBytes:]
		e[0] = byte(sizes[i])       // width; 0 would mean 256, which we do not use
		e[1] = byte(sizes[i])       // height
		e[2] = 0                    // colour count: 0 for >8bpp
		e[3] = 0                    // reserved
		binary.LittleEndian.PutUint16(e[4:], 1)  // colour planes
		binary.LittleEndian.PutUint16(e[6:], 32) // bits per pixel
		binary.LittleEndian.PutUint32(e[8:], uint32(len(frame)))
		binary.LittleEndian.PutUint32(e[12:], offset)

		out = append(out, frame...)
		offset += uint32(len(frame))
	}

	return out
}

// encodeDIB renders one image as the BITMAPINFOHEADER + BGRA XOR bitmap plus
// AND mask that an .ico directory entry points at.
//
// The quirks here are all format requirements rather than choices:
//
//   - Height in the header is twice the visible height, because a DIB inside an
//     icon carries the 1-bit transparency mask after the colour bitmap.
//   - Rows are stored bottom-up, the opposite of image.RGBA.
//   - Pixels are BGRA, not RGBA.
//   - The AND mask is padded to a 4-byte boundary per row. Because the colour
//     data is 32-bit and fully opaque-alpha-aware, an all-zero mask is correct
//     and simplest.
func encodeDIB(img *image.RGBA) []byte {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()

	// XOR bitmap: 4 bytes per pixel, bottom-up.
	xor := make([]byte, w*h*4)
	for y := 0; y < h; y++ {
		srcY := b.Max.Y - 1 - y
		row := y * w * 4
		for x := 0; x < w; x++ {
			c := img.RGBAAt(b.Min.X+x, srcY)
			i := row + x*4
			xor[i+0] = c.B
			xor[i+1] = c.G
			xor[i+2] = c.R
			xor[i+3] = c.A
		}
	}

	// AND mask: 1 bit per pixel, padded so each row starts on a 4-byte
	// boundary. 16px and 48px rows are already 2 and 6 bytes so they need
	// padding to 4 and 8; 32px rows are exactly 4.
	maskStride := ((w + 31) / 32) * 4
	mask := make([]byte, maskStride*h)

	hdr := make([]byte, dibHeaderBytes)
	binary.LittleEndian.PutUint32(hdr[0:], dibHeaderBytes)
	binary.LittleEndian.PutUint32(hdr[4:], uint32(w))
	binary.LittleEndian.PutUint32(hdr[8:], uint32(h*2)) // colour + mask
	binary.LittleEndian.PutUint16(hdr[12:], 1)         // planes
	binary.LittleEndian.PutUint16(hdr[14:], 32)        // bit count
	binary.LittleEndian.PutUint32(hdr[20:], uint32(len(xor)))

	out := make([]byte, 0, dibHeaderBytes+len(xor)+len(mask))
	out = append(out, hdr...)
	out = append(out, xor...)
	out = append(out, mask...)
	return out
}

// shieldRow is the half-width profile of the shield silhouette on the 16x16
// design grid, one entry per row: the leftmost and rightmost column that is
// inside the shape.
//
// The shape is a heraldic shield: narrow flat top, shoulders that step out over
// the first few rows, straight sides through the middle, then a taper to a
// point at the bottom.
var shieldRow = [16][2]int{
	{5, 10},
	{4, 11},
	{3, 12},
	{2, 13},
	{1, 14},
	{1, 14},
	{0, 15},
	{0, 15},
	{0, 15},
	{0, 15},
	{1, 14},
	{2, 13},
	{3, 12},
	{4, 11},
	{6, 9},
	{7, 8},
}

// letterA is the block "A" reversed out of the shield, 9 by 9.
//
// The strokes are two cells thick and the counters are four. A thinner letter
// was tried first and is illegible at 16px: with one-cell strokes the counter
// inside the bowl is a single pixel and the counter under the crossbar is one
// or two, so at the sizes the notification area actually uses the letter reads
// as a solid blob with a notch rather than as a letter. Two-cell strokes with a
// four-cell counter survive the downscale.
var letterA = [9][9]byte{
	{0, 0, 1, 1, 1, 1, 1, 0, 0},
	{0, 1, 1, 0, 0, 0, 1, 1, 0},
	{1, 1, 0, 0, 0, 0, 0, 1, 1},
	{1, 1, 0, 0, 0, 0, 0, 1, 1},
	{1, 1, 1, 1, 1, 1, 1, 1, 1},
	{1, 1, 0, 0, 0, 0, 0, 1, 1},
	{1, 1, 0, 0, 0, 0, 0, 1, 1},
	{1, 1, 0, 0, 0, 0, 0, 1, 1},
	{1, 1, 0, 0, 0, 0, 0, 1, 1},
}

// Placement of letterA on the design grid. Rows 4-12 are where the silhouette is
// wide enough to hold it; horizontally it is centred on the full-width rows.
const (
	letterCol = 3
	letterRow = 4
)

// drawTrayGlyph renders the mark into a plain image.
//
// The glyph is generated from a silhouette profile rather than a hand-typed
// pixel table. A literal 16x16 table is easy to get subtly wrong and impossible
// to review: the previous one looked plausible but rendered as meaningless
// vertical stripes rather than the letter it was meant to be. Deriving the
// outline from the fill - any filled cell with an unfilled four-neighbour is
// ink - means the border is always exactly one pixel thick and always closed,
// no matter how the profile is edited.
//
// Split out from the encoder because image.RGBA can be inspected with At(),
// which is what makes the glyph testable at all - and an icon that renders
// blank is invisible, which is the failure this whole change exists to prevent.
func drawTrayGlyph(size int, body color.RGBA) *image.RGBA {
	if size <= 0 {
		size = trayIconMid
	}

	img := image.NewRGBA(image.Rect(0, 0, size, size))

	// Scale the 16x16 design grid to the requested size so the glyph stays
	// proportional across DPI buckets.
	u := size / 16
	if u < 1 {
		u = 1
	}

	// Transparent background - a solid square in the notification area looks
	// like a placeholder.
	draw.Draw(img, img.Bounds(), image.NewUniform(color.RGBA{}), image.Point{}, draw.Src)

	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			if !shieldInside(x, y) {
				continue
			}
			// Solid ink silhouette with the letter reversed out in the body
			// colour.
			//
			// The obvious alternative - a one-pixel ink outline around a filled
			// body - was tried and does not work. The silhouette steps in and
			// out by a single column per row, so a one-pixel outline derived
			// from it breaks into disconnected specks along every step, and at
			// 16px the interior fill is barely larger than the letter, so the
			// two merge into a blob. A solid shape has no outline to break, and
			// a mint letter on near-black is the highest-contrast arrangement
			// available at this size.
			c := trayInk
			if inLetter(x, y) {
				c = body
			}

			r := image.Rect(x*u, y*u, (x+1)*u, (y+1)*u)
			draw.Draw(img, r, image.NewUniform(c), image.Point{}, draw.Src)
		}
	}

	return img
}

// shieldInside reports whether a design-grid cell falls within the shield.
// Out-of-range coordinates are outside, which is what lets the outline test
// above work without special-casing the edges.
func shieldInside(x, y int) bool {
	if y < 0 || y >= len(shieldRow) {
		return false
	}
	lo, hi := shieldRow[y][0], shieldRow[y][1]
	return x >= lo && x <= hi
}

// inLetter reports whether a cell falls on a stroke of the "A".
func inLetter(x, y int) bool {
	r, c := y-letterRow, x-letterCol
	if r < 0 || r >= len(letterA) || c < 0 || c >= len(letterA[0]) {
		return false
	}
	return letterA[r][c] == 1
}

// trayBodyForState recolours the icon to reflect agent state without needing a
// separate asset per state: the shield's body swaps between the accent mint and
// the fail red, and the outline stays ink so the glyph remains legible on any
// taskbar.
func trayBodyForState(state string) color.RGBA {
	switch state {
	case "assessing":
		// Amber for work in progress; matches the dashboard's warn colour.
		return trayWarn
	case "disconnected", "error":
		return trayFail
	default:
		return trayAccent
	}
}